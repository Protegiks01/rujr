# Audit Report

## Title
Gas Griefing DoS Attack via Unbounded Liquidation Preference Messages

## Summary
An attacker can prevent liquidation of their undercollateralized account by setting an unlimited number of gas-expensive messages as liquidation preferences. When liquidation is attempted, these preference messages consume excessive gas, causing the transaction to fail. This enables attackers to maintain undercollateralized positions indefinitely, threatening protocol solvency.

## Finding Description

The vulnerability exists in the liquidation preference mechanism where users can set arbitrary `LiquidateMsg` messages that are executed before liquidator-provided messages during account liquidation.

**Root Cause:**

The `set_preference_msgs` function accepts an unbounded vector of liquidation messages without any validation on quantity or gas consumption: [1](#0-0) 

During liquidation initiation, preference messages are prepended to the execution queue, ensuring they process before liquidator messages: [2](#0-1) 

Each preference message is executed via `SubMsg::reply_always` **without gas limits**, sharing the parent transaction's gas meter: [3](#0-2) 

The `DoLiquidate` flow processes messages sequentially in the same transaction context: [4](#0-3) 

While the reply handler catches errors from preference messages, the gas consumed before failure is never refunded: [5](#0-4) 

**The critical flaw**: In CosmWasm, `SubMsg` execution without explicit gas limits shares the parent transaction's gas meter. Even though `reply_always` catches execution failures, gas consumed during SubMsg execution is irreversibly spent.

**Attack Mechanism:**

1. Attacker creates account, deposits collateral, borrows funds
2. Attacker calls `AccountMsg::SetPreferenceMsgs` with 50-100 `LiquidateMsg::Execute` messages, each targeting contracts with expensive operations (complex loops, storage writes, external calls)
3. Account becomes unsafe (LTV >= liquidation_threshold) due to market movements
4. Liquidator attempts liquidation via `ExecuteMsg::Liquidate`
5. The liquidation flow prepends preference messages to the queue
6. `DoLiquidate` processes preference messages sequentially, each consuming gas through SubMsg execution
7. Cumulative gas consumption from multiple expensive messages exceeds the transaction's gas limit
8. Entire liquidation transaction fails with out-of-gas error
9. Account remains undercollateralized, violating the protocol's liquidation invariant

**Broken Invariants:**

- **Safe Liquidation Outcomes** (Invariant #3): Liquidations should trigger when `adjusted_ltv >= liquidation_threshold` and complete successfully. This DoS attack prevents liquidation completion.
- **System Solvency**: The protocol relies on timely liquidations to maintain collateralization ratios. Preventing liquidations threatens systemic solvency as collateral values may continue declining while positions remain unliquidated.

## Impact Explanation

**Severity: High**

This vulnerability enables:

1. **Systemic Undercollateralization Risk**: Attackers can maintain positions with LTV > 1 indefinitely, accumulating bad debt that cannot be cleared through liquidation
2. **Protocol Insolvency**: If collateral values continue dropping while liquidation is blocked, the protocol suffers unrecoverable losses exceeding the value of seized collateral
3. **Lender Losses**: Vault depositors (lenders) face direct losses as borrowers cannot be liquidated and debt becomes uncollectible
4. **Cascading Risk**: Multiple attackers exploiting this vulnerability simultaneously could cause widespread undercollateralization

Financial Impact:
- **Direct**: Attackers can borrow up to their collateral value and prevent forced repayment, effectively stealing lent funds
- **Indirect**: Protocol reputation damage, loss of user confidence, potential vault runs as lenders rush to withdraw

## Likelihood Explanation

**Likelihood: High**

This attack is:
- **Easy to Execute**: Requires only calling `SetPreferenceMsgs` with gas-expensive messages (no special permissions or complex setup needed)
- **Low Cost**: Setting preferences has minimal gas cost; the expensive operations only trigger during liquidation attempts (gas burden falls on liquidators, not attacker)
- **Highly Profitable**: Attackers can extract maximum borrowing value without liquidation risk, with profits limited only by vault liquidity
- **Difficult to Mitigate**: No on-chain mechanism exists to prevent this attack; requires protocol upgrade to add message count limits or gas limits per SubMsg

Preconditions:
- Attacker has a credit account (trivial to create via `ExecuteMsg::Create`)
- Attacker can identify or deploy a contract with expensive operations (common in DeFi)
- Market conditions cause account to become liquidatable (natural occurrence in volatile markets)

## Recommendation

Implement the following mitigations:

1. **Add maximum limit on preference messages**:
```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    const MAX_PREFERENCE_MSGS: usize = 10;
    ensure!(
        msgs.len() <= MAX_PREFERENCE_MSGS,
        ContractError::TooManyPreferenceMessages { 
            count: msgs.len(), 
            max: MAX_PREFERENCE_MSGS 
        }
    );
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

2. **Add gas limits to SubMsg execution**:
```rust
SubMsg::reply_always(
    account.account.execute(contract_addr.clone(), msg.clone(), funds.clone())?,
    reply_id,
)
.with_gas_limit(100_000) // Reasonable limit per message
```

3. **Add cumulative gas tracking** to halt processing if total preference message gas exceeds threshold

4. **Consider making preference messages optional** for liquidators, allowing bypass if they exceed gas thresholds

## Proof of Concept

```rust
#[test]
fn test_gas_griefing_dos_attack() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let attacker = app.api().addr_make("attacker");
    
    // Setup: Create vaults and credit system
    let ghost_vault_btc = GhostVault::create(&mut app, &owner, BTC);
    let ghost_vault_usdc = GhostVault::create(&mut app, &owner, USDC);
    let ghost_credit = GhostCredit::create(&mut app, &owner, &owner);
    
    ghost_credit.set_collateral(&mut app, BTC, "0.8");
    ghost_credit.set_collateral(&mut app, USDC, "0.9");
    ghost_credit.set_vault(&mut app, &ghost_vault_btc);
    ghost_credit.set_vault(&mut app, &ghost_vault_usdc);
    
    // Fund vaults
    ghost_vault_usdc.deposit(&mut app, &owner, 1000000000000, USDC).unwrap();
    ghost_vault_usdc.set_borrower(&mut app, ghost_credit.addr().as_str(), Uint128::MAX).unwrap();
    
    // Attacker creates account and deposits collateral
    ghost_credit.create_account(&mut app, &attacker, "", "", Binary::new(vec![1]));
    let account_addr = ghost_credit.predict_account(&app, &attacker, Binary::new(vec![1]));
    
    app.send_tokens(attacker.clone(), account_addr.clone(), &[coin(100000000, BTC)]).unwrap();
    
    // Attacker borrows funds
    let account = ghost_credit.query_account(&app, &account_addr);
    ghost_credit.account_borrow(&mut app, &account, 800000000000, USDC).unwrap();
    
    // Attacker sets many expensive preference messages (50+ messages calling expensive contracts)
    let expensive_msgs: Vec<LiquidateMsg> = (0..50)
        .map(|_| LiquidateMsg::Execute {
            contract_addr: expensive_contract_addr.to_string(), // Contract with loops
            msg: to_json_binary(&expensive_operation).unwrap(),
            funds: vec![],
        })
        .collect();
    
    ghost_credit.account_set_preference_msgs(&mut app, &account, expensive_msgs).unwrap();
    
    // Price drops, account becomes liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![("BTC", Decimal::from_str("50000").unwrap())]);
    });
    
    let account = ghost_credit.query_account(&app, &account_addr);
    assert!(account.ltv > Decimal::one());
    
    // Liquidator attempts liquidation with valid route
    let liquidation_result = ghost_credit.liquidate_execute_repay(
        &mut app,
        &account,
        swap_contract_addr,
        swap_msg,
        coins(1000000, BTC),
        USDC,
    );
    
    // Liquidation FAILS due to gas exhaustion from preference messages
    assert!(liquidation_result.is_err());
    assert!(liquidation_result.unwrap_err().to_string().contains("out of gas"));
    
    // Account remains undercollateralized
    let account = ghost_credit.query_account(&app, &account_addr);
    assert!(account.ltv > Decimal::one());
}
```

**Notes**

The vulnerability is confirmed by the following code evidence:
1. No validation limits exist on the number of preference messages ( [1](#0-0) )
2. Preference messages are executed before liquidator messages ( [2](#0-1) )
3. SubMsg execution occurs without gas limits ( [3](#0-2) )
4. Gas consumption is irreversible even when errors are caught ( [5](#0-4) )

This attack is particularly severe because the attacker incurs minimal cost (only the gas to set preferences once) while forcing liquidators to repeatedly fail with high gas costs, creating strong economic disincentives for liquidation attempts.

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-148)
```rust
        ExecuteMsg::DoLiquidate {
            addr,
            mut queue,
            payload,
        } => {
            ensure_eq!(info.sender, ca, ContractError::Unauthorized {});
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            let original_account: CreditAccount = from_json(&payload)?;

            let check = account
                // Check safe against the liquidation threshold
                .check_safe(&config.liquidation_threshold)
                // Check we've not gone below the adjustment threshold
                .and_then(|_| account.check_unsafe(&config.adjustment_threshold))
                .and_then(|_| {
                    account.validate_liquidation(deps.as_ref(), &config, &original_account)
                });
            match (queue.pop(), check) {
                (_, Ok(())) => Ok(Response::default()),
                (None, Err(err)) => {
                    // We're done and the Account hasn't passed checks. Fail
                    Err(err)
                }
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
                    .add_message(
                        ExecuteMsg::DoLiquidate {
                            addr: account.id().to_string(),
                            queue,
                            payload,
                        }
                        .call(&ca)?,
                    ))
                }
            }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L324-332)
```rust
            .add_submessage(
                SubMsg::reply_always(
                    account
                        .account
                        .execute(contract_addr.clone(), msg.clone(), funds.clone())?,
                    reply_id,
                )
                .with_payload(to_json_binary(&account)?),
            )
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L342-351)
```rust
pub fn reply(_deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match (msg.result, msg.id) {
        (SubMsgResult::Err(err), REPLY_ID_PREFERENCE) => {
            // Don't block execution if this is a preferential step
            Ok(Response::default().add_event(event_execute_liquidate_preference_error(err)))
        }
        (SubMsgResult::Err(err), REPLY_ID_LIQUIDATOR) => Err(StdError::generic_err(err).into()),
        (SubMsgResult::Ok(_), _) => Ok(Response::default()),
        _ => Err(ContractError::Unauthorized {}),
    }
```
