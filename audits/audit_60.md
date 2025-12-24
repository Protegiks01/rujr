# Audit Report

## Title
Critical Liquidator Fee Misdirection: Fees Sent to Contract Instead of Liquidator

## Summary
The liquidation mechanism fails to properly track and reward liquidators. When `ExecuteMsg::DoLiquidate` recursively processes liquidation messages, the original liquidator's address is lost, causing the 0.5% liquidator fee to be sent to the registry contract itself instead of the actual liquidator who triggered the liquidation. This completely breaks the economic incentive model for permissionless liquidations.

## Finding Description

The vulnerability exists in how the liquidation flow handles the liquidator's identity across the recursive `DoLiquidate` execution pattern.

**Flow Analysis:**

1. External liquidator calls `ExecuteMsg::Liquidate` where `info.sender` = liquidator address [1](#0-0) 

2. An event is emitted correctly identifying the caller, then `DoLiquidate` is invoked as an internal message [2](#0-1) 

3. When `DoLiquidate` executes, it enforces that `info.sender` must equal the contract address (self-call) [3](#0-2) 

4. `DoLiquidate` calls `execute_liquidate` passing the current `info` parameter [4](#0-3) 

5. In `execute_liquidate`, the liquidator fee is calculated and sent to `info.sender` [5](#0-4) 

**The Bug:** Since `info` in step 4 comes from `DoLiquidate` where `info.sender` = contract address, the liquidator fee at line 309 is sent to the contract itself, not the original liquidator.

**Broken Invariant:** This violates the "Fee-First Liquidation Repay" invariant by failing to properly distribute liquidator fees to their intended recipients. The README explicitly states there is a "0.5% liquidator fee taken from the repaid debt" as an economic incentive.

The payload passed through `DoLiquidate` only contains the serialized account state, not the original liquidator address: [6](#0-5) 

There is no mechanism in the protocol to withdraw or redistribute accumulated fees from the contract address.

## Impact Explanation

**Critical Severity** - This issue causes:

1. **Direct Loss of Funds:** Liquidators never receive their 0.5% fee, losing all expected compensation
2. **Protocol Insolvency Risk:** Without economic incentives, liquidations may not occur promptly or at all
3. **Permanent Fee Lock:** Fees accumulate in the registry contract with no withdrawal mechanism
4. **Systemic Undercollateralization:** Delayed/missing liquidations lead to bad debt accumulation

Every liquidation in the protocol suffers from this bug. With the documented 0.5% liquidator fee, on a $100,000 liquidation, $500 would be incorrectly sent to the contract instead of the liquidator.

## Likelihood Explanation

**Likelihood: Certain (100%)** - This bug affects every single liquidation:

- No preconditions needed beyond a liquidatable account
- Happens automatically in the recursive `DoLiquidate` pattern
- Already present in deployed code
- Cannot be worked around by liquidators
- The test suite doesn't verify fee distribution to liquidator addresses, only using `account.owner` as the liquidator in tests

## Recommendation

**Solution:** Store the original liquidator address in the `DoLiquidate` payload so it can be properly referenced when distributing fees.

**Code Fix:**

1. Modify `ExecuteMsg::DoLiquidate` to include the liquidator address:
```rust
DoLiquidate {
    addr: String,
    queue: Vec<(LiquidateMsg, bool)>,
    payload: Binary,
    liquidator: Addr,  // ADD THIS
}
```

2. Update the `Liquidate` handler to pass the liquidator:
```rust
ExecuteMsg::DoLiquidate {
    addr: account.id().to_string(),
    queue,
    payload: to_json_binary(&account)?,
    liquidator: info.sender.clone(),  // ADD THIS
}
```

3. Update `execute_liquidate` signature to accept the liquidator address:
```rust
pub fn execute_liquidate(
    deps: Deps,
    env: Env,
    info: MessageInfo,
    config: &Config,
    msg: LiquidateMsg,
    account: &CreditAccount,
    reply_id: u64,
    liquidator: &Addr,  // ADD THIS
) -> Result<Response, ContractError>
```

4. Send fees to the liquidator instead of info.sender:
```rust
.add_message(BankMsg::Send {
    to_address: liquidator.to_string(),  // CHANGE FROM info.sender
    amount: coins(liquidator_fee.u128(), denom.clone()),
})
```

## Proof of Concept

Add this test to `contracts/rujira-ghost-credit/src/tests/contract.rs`:

```rust
#[test]
fn test_liquidator_fee_misdirection() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let liquidator = app.api().addr_make("liquidator");  // Separate liquidator
    let fees = app.api().addr_make("fees");
    
    // Setup vault and credit system
    let vault = setup_vault(&mut app, &owner, USDC);
    let credit = setup_credit(&mut app, &owner, &fees, vault.code_id());
    credit.set_vault(&mut app, &vault);
    credit.set_collateral(&mut app, BTC, "0.8");
    
    let account = create_account(&mut app, &credit, &owner);
    
    // Fund account with collateral and borrow
    app.send_tokens(owner.clone(), account.account.clone(), coins(1280, BTC)).unwrap();
    credit.account_borrow(&mut app, &account, 1000, USDC).unwrap();
    
    // Make account liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![("BTC", Decimal::from_str("0.85").unwrap())]);
    });
    
    let liquidator_balance_before = app.wrap().query_balance(&liquidator, USDC).unwrap().amount;
    let contract_balance_before = app.wrap().query_balance(credit.addr(), USDC).unwrap().amount;
    
    // Liquidate using separate liquidator address (NOT owner)
    app.execute_contract(
        liquidator.clone(),
        credit.addr().clone(),
        &ExecuteMsg::Liquidate {
            addr: account.account.to_string(),
            msgs: vec![LiquidateMsg::Repay(USDC.to_string())],
        },
        &[],
    ).unwrap();
    
    let liquidator_balance_after = app.wrap().query_balance(&liquidator, USDC).unwrap().amount;
    let contract_balance_after = app.wrap().query_balance(credit.addr(), USDC).unwrap().amount;
    
    // BUG: Liquidator received NO fee
    assert_eq!(liquidator_balance_after, liquidator_balance_before);
    
    // BUG: Fee went to contract instead
    let expected_fee = Uint128::from(5u128); // 0.5% of 1000
    assert_eq!(contract_balance_after - contract_balance_before, expected_fee);
}
```

**Expected behavior:** Liquidator should receive the 0.5% fee

**Actual behavior:** Fee is sent to the registry contract address, liquidator receives nothing

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-99)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
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

            Ok(Response::default()
                .add_message(
                    ExecuteMsg::DoLiquidate {
                        addr: account.id().to_string(),
                        queue,
                        payload: to_json_binary(&account)?,
                    }
                    .call(&ca)?,
                )
                .add_event(event_execute_liquidate(&account, &info.sender)))
        }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-105)
```rust
        ExecuteMsg::DoLiquidate {
            addr,
            mut queue,
            payload,
        } => {
            ensure_eq!(info.sender, ca, ContractError::Unauthorized {});
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L285-311)
```rust
            let liquidator_fee = balance.amount.multiply_ratio(
                config.fee_liquidator.numerator(),
                config.fee_liquidator.denominator(),
            );

            let repay_amount = balance.amount.sub(liquidation_fee).sub(liquidator_fee);

            Ok(Response::default()
                .add_message(
                    account
                        .account
                        .send(env.contract.address.to_string(), vec![balance.clone()])?,
                )
                .add_message(
                    vault.market_msg_repay(
                        Some(delegate),
                        &coin(repay_amount.u128(), denom.clone()),
                    )?,
                )
                .add_message(BankMsg::Send {
                    to_address: config.fee_address.to_string(),
                    amount: coins(liquidation_fee.u128(), denom.clone()),
                })
                .add_message(BankMsg::Send {
                    to_address: info.sender.to_string(),
                    amount: coins(liquidator_fee.u128(), denom.clone()),
                })
```

**File:** contracts/rujira-ghost-credit/src/events.rs (L66-71)
```rust
pub fn event_execute_liquidate(account: &CreditAccount, caller: &Addr) -> Event {
    Event::new(format!("{}/account.liquidate", env!("CARGO_PKG_NAME")))
        .add_attribute("owner", account.owner.clone())
        .add_attribute("address", account.id().to_string())
        .add_attribute("caller", caller.to_string())
}
```
