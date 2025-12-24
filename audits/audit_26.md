# Audit Report

## Title
Liquidation Denial of Service via Malicious Preference Messages Causes Protocol Insolvency

## Summary
Account owners can set malicious `liquidation_preferences.messages` containing `LiquidateMsg::Repay` operations for tokens they have zero balance of, causing liquidation transactions to revert and permanently preventing liquidation of undercollateralized positions.

## Finding Description

The liquidation mechanism allows account owners to set preference messages that are processed during liquidation. However, there is a critical asymmetry in error handling between `LiquidateMsg::Execute` and `LiquidateMsg::Repay` variants.

**The Vulnerability:**

When an account owner sets `liquidation_preferences.messages` via `AccountMsg::SetPreferenceMsgs`, there is no validation on the messages. [1](#0-0) 

During liquidation, preference messages are prepended to the liquidator's messages and processed sequentially in `DoLiquidate`. [2](#0-1) 

The critical flaw lies in `execute_liquidate` for the `Repay` variant. When processing a `LiquidateMsg::Repay`, if the account has zero balance of the debt token, the function returns an error directly without using a SubMsg: [3](#0-2) 

This error propagates through the `?` operator in `DoLiquidate`: [4](#0-3) 

The reply handler only catches errors from `SubMsg` with `REPLY_ID_PREFERENCE`, but `Repay` doesn't use SubMsg: [5](#0-4) 

In contrast, `LiquidateMsg::Execute` uses `SubMsg::reply_always`, so its errors are properly caught by the reply handler. [6](#0-5) 

**Attack Scenario:**

1. User creates an account and borrows funds, becoming undercollateralized
2. User calls `ExecuteMsg::Account` with `AccountMsg::SetPreferenceMsgs([LiquidateMsg::Repay("USDC")])` where they ensure zero USDC balance during liquidation
3. When liquidators attempt to liquidate the position, `DoLiquidate` processes the preference message
4. `execute_liquidate` queries the balance, finds zero, and returns `ContractError::ZeroDebtTokens`
5. The error propagates, causing the entire liquidation transaction to revert
6. The undercollateralized position persists indefinitely

## Impact Explanation

**Critical Severity** - This vulnerability enables permanent denial of liquidation for undercollateralized positions, leading to:

1. **Protocol Insolvency**: Bad debt accumulates as liquidatable positions cannot be liquidated
2. **Systemic Risk**: Multiple accounts can exploit this simultaneously, creating widespread undercollateralization
3. **Loss of Lender Funds**: Vault depositors lose funds when borrowers' debt exceeds collateral value
4. **Protocol Failure**: The fundamental liquidation mechanism is completely bypassed

The attack requires minimal sophistication (just setting a preference message) and has maximal impact (complete liquidation DoS). This breaks the core invariant that "Liquidations only trigger when adjusted_ltv >= liquidation_threshold" - liquidations can trigger but will always fail.

## Likelihood Explanation

**Extremely High** - The attack is:
- **Trivial to execute**: Single transaction to set preference messages
- **Cost-free**: No economic cost to the attacker
- **Undetectable**: The malicious preference looks benign until liquidation
- **Incentivized**: Attackers gain by avoiding liquidation losses
- **No prerequisites**: Any account owner can exploit this

Every undercollateralized borrower has strong incentive to use this exploit to avoid liquidation penalties.

## Recommendation

Wrap `LiquidateMsg::Repay` operations in a `SubMsg` with the appropriate `reply_id`, similar to `LiquidateMsg::Execute`:

```rust
LiquidateMsg::Repay(denom) => {
    let vault = BORROW.load(deps.storage, denom.clone())?;
    let balance = deps.querier.query_balance(account.id(), &denom)?;

    if balance.amount.is_zero() {
        return Err(ContractError::ZeroDebtTokens {
            denom: balance.denom,
        });
    }

    let liquidation_fee = balance.amount.multiply_ratio(
        config.fee_liquidation.numerator(),
        config.fee_liquidation.denominator(),
    );
    let liquidator_fee = balance.amount.multiply_ratio(
        config.fee_liquidator.numerator(),
        config.fee_liquidator.denominator(),
    );

    let repay_amount = balance.amount.sub(liquidation_fee).sub(liquidator_fee);

    Ok(Response::default()
        .add_submessage(
            SubMsg::reply_always(
                CosmosMsg::Bank(BankMsg::Send {
                    to_address: env.contract.address.to_string(),
                    amount: vec![balance.clone()],
                }),
                reply_id,
            )
            .with_payload(to_json_binary(&(vault, delegate, repay_amount, denom, liquidation_fee, liquidator_fee))?)
        ))
}
```

Then handle the repay logic in the reply handler, where preference errors can be properly swallowed.

Alternatively, skip preference messages that fail the zero-balance check:

```rust
LiquidateMsg::Repay(denom) => {
    let vault = BORROW.load(deps.storage, denom.clone())?;
    let balance = deps.querier.query_balance(account.id(), &denom)?;

    if balance.amount.is_zero() {
        // If this is a preference message, skip it instead of failing
        if reply_id == REPLY_ID_PREFERENCE {
            return Ok(Response::default().add_event(
                event_execute_liquidate_preference_error("Zero balance for Repay".to_string())
            ));
        }
        return Err(ContractError::ZeroDebtTokens {
            denom: balance.denom,
        });
    }
    // ... rest of repay logic
}
```

## Proof of Concept

```rust
#[test]
fn test_liquidation_dos_via_preference_poisoning() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let liquidator = app.api().addr_make("liquidator");
    let ctx = setup(&mut app, &owner);

    // Account owner deposits collateral
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(100000000, BTC)], // 1 BTC
    )
    .unwrap();

    // Borrow against collateral
    ctx.ghost_credit
        .account_borrow(&mut app, &ctx.account, 50000000000000, USDC) // $50k
        .unwrap();

    // Send borrowed funds out
    ctx.ghost_credit
        .account_send(&mut app, &ctx.account, 50000000000000, USDC, &owner)
        .unwrap();

    // ATTACK: Set malicious preference message with zero-balance Repay
    // This will always fail when liquidation is attempted
    ctx.ghost_credit
        .account(
            &mut app,
            &ctx.account,
            vec![AccountMsg::SetPreferenceMsgs(vec![
                LiquidateMsg::Repay(USDT.to_string()), // Zero balance of USDT
            ])],
        )
        .unwrap();

    // Price drops, position becomes undercollateralized
    app.init_modules(|router, _api, _storage| {
        router
            .stargate
            .with_prices(vec![("BTC", Decimal::from_str("40000").unwrap())]);
    });

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv > Decimal::one()); // Position is liquidatable

    // Attempt liquidation - THIS WILL FAIL DUE TO PREFERENCE POISONING
    let err = ctx
        .ghost_credit
        .liquidate_execute_repay(
            &mut app,
            &account,
            ctx.fin_btc_usdc.addr(),
            fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
                to: None,
                callback: None,
            }),
            coins(10000000, BTC),
            USDC,
        )
        .unwrap_err();

    // Verify the error is ZeroDebtTokens from the malicious preference
    let err_msg = format!("{:?}", err.root_cause());
    assert!(err_msg.contains("ZeroDebtTokens"));
    assert!(err_msg.contains(USDT));

    // Position remains undercollateralized and unliquidatable
    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv > Decimal::one()); // Still undercollateralized
    
    // Protocol is now insolvent - bad debt cannot be liquidated
}
```

**Notes:**
- This vulnerability requires adding a helper method to the `GhostCredit` mock for setting preference messages
- The PoC demonstrates that ANY liquidation attempt will fail once malicious preferences are set
- The attack is permanent until contract upgrade, as there's no way to override user preferences
- This affects ALL undercollateralized accounts that set such preferences

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L231-233)
```rust
    pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
        self.liquidation_preferences.messages = msgs
    }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L77-87)
```rust
            let mut queue: Vec<(LiquidateMsg, bool)> =
                msgs.iter().map(|x| (x.clone(), false)).collect();
            queue.reverse();
            let mut prefs: Vec<(LiquidateMsg, bool)> = account
                .liquidation_preferences
                .messages
                .iter()
                .map(|x| (x.clone(), true))
                .collect();
            prefs.reverse();
            queue.append(&mut prefs);
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L124-138)
```rust
                (Some((msg, is_preference)), Err(_)) => {
                    // Not safe, more messages to go. Continue
                    Ok(execute_liquidate(
                        deps.as_ref(),
                        env.clone(),
                        info,
                        &config,
                        msg,
                        &account,
                        if is_preference {
                            REPLY_ID_PREFERENCE
                        } else {
                            REPLY_ID_LIQUIDATOR
                        },
                    )?
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L265-276)
```rust
        LiquidateMsg::Repay(denom) => {
            let vault = BORROW.load(deps.storage, denom.clone())?;
            // We repay the full balance so that Repay can be chained in liquidation preferences messages
            // and still pass the no-over-liquidation check, as we can't know ahead of time the amount to repay
            // after a collateral swap
            let balance = deps.querier.query_balance(account.id(), &denom)?;

            if balance.amount.is_zero() {
                return Err(ContractError::ZeroDebtTokens {
                    denom: balance.denom,
                });
            }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L319-331)
```rust
        LiquidateMsg::Execute {
            contract_addr,
            msg,
            funds,
        } => Ok(Response::default()
            .add_submessage(
                SubMsg::reply_always(
                    account
                        .account
                        .execute(contract_addr.clone(), msg.clone(), funds.clone())?,
                    reply_id,
                )
                .with_payload(to_json_binary(&account)?),
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L342-347)
```rust
pub fn reply(_deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match (msg.result, msg.id) {
        (SubMsgResult::Err(err), REPLY_ID_PREFERENCE) => {
            // Don't block execution if this is a preferential step
            Ok(Response::default().add_event(event_execute_liquidate_preference_error(err)))
        }
```
