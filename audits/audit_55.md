# Audit Report

## Title
Liquidator Fees Incorrectly Sent to Contract Address, Breaking Liquidation Incentive Mechanism

## Summary
Liquidation fees intended for liquidators are incorrectly sent to the registry contract address instead of the actual liquidator who initiated the liquidation. This occurs because the `info.sender` context is overwritten when `ExecuteMsg::Liquidate` creates a self-call to `ExecuteMsg::DoLiquidate`, breaking the liquidation incentive mechanism and causing protocol insolvency.

## Finding Description

The Rujira protocol's liquidation mechanism is designed to incentivize permissionless liquidators by rewarding them with `config.fee_liquidator` of the repaid debt amount. [1](#0-0) 

However, the current implementation has a critical flaw in how the liquidator's address is tracked through the liquidation flow:

**Step 1**: A liquidator calls `ExecuteMsg::Liquidate` with their address as `info.sender` [2](#0-1) 

**Step 2**: The `Liquidate` handler creates a `WasmMsg::Execute` to call `ExecuteMsg::DoLiquidate` on itself via `.call(&ca)` [3](#0-2) 

**Step 3**: When `DoLiquidate` executes, CosmWasm sets `info.sender` to the contract address (since the contract sent the message to itself), which is enforced by the validation: [4](#0-3) 

**Step 4**: The `info` parameter (with `info.sender = contract_address`) is passed to `execute_liquidate`: [5](#0-4) 

**Step 5**: When fees are distributed in `execute_liquidate`, the liquidator fee is sent to `info.sender.to_string()`, which is now the contract address, not the original liquidator: [6](#0-5) 

The original liquidator's address is captured in the event emission but is never passed through to the fee distribution logic: [7](#0-6) 

This breaks **Invariant #6 (Fee-First Liquidation Repay)** as liquidators never receive their intended fees, and there is no mechanism in the contract to withdraw accumulated fees from the contract address.

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Protocol Insolvency**: Without financial incentives, liquidators will not liquidate undercollateralized positions, allowing bad debt to accumulate and threatening protocol solvency
2. **Fund Loss**: Liquidator fees (0.5% of repaid debt per README) accumulate in the contract address with no withdrawal mechanism, effectively locking these funds permanently
3. **Broken Core Mechanism**: The entire permissionless liquidation system is non-functional as designed

For a position with $100,000 in debt being liquidated, the intended $500 liquidator fee (0.5%) would be sent to the contract instead of the liquidator, providing zero incentive for liquidation execution.

## Likelihood Explanation

**Likelihood: HIGH** - This bug affects every single liquidation in the protocol:

- No special conditions required
- Affects all liquidation attempts regardless of message composition
- Already occurring in current deployment (if any liquidations have been executed, fees are accumulating in contract)
- Liquidators will quickly discover they receive no fees and stop liquidating positions
- No attacker action needed - the bug is inherent to the implementation

## Recommendation

The liquidator's address must be tracked through the recursive `DoLiquidate` calls. Add the liquidator address to the `DoLiquidate` message payload:

**Modified ExecuteMsg enum**:
```rust
DoLiquidate {
    addr: String,
    queue: Vec<(LiquidateMsg, bool)>,
    payload: Binary,
    liquidator: Addr,  // Add this field
}
```

**Modified Liquidate handler**:
```rust
ExecuteMsg::Liquidate { addr, msgs } => {
    // ... existing code ...
    Ok(Response::default()
        .add_message(
            ExecuteMsg::DoLiquidate {
                addr: account.id().to_string(),
                queue,
                payload: to_json_binary(&account)?,
                liquidator: info.sender.clone(),  // Capture liquidator
            }
            .call(&ca)?,
        )
        .add_event(event_execute_liquidate(&account, &info.sender)))
}
```

**Modified DoLiquidate handler to pass liquidator through**:
```rust
ExecuteMsg::DoLiquidate {
    addr,
    mut queue,
    payload,
    liquidator,  // Add this parameter
} => {
    // ... existing validation ...
    (Some((msg, is_preference)), Err(_)) => {
        Ok(execute_liquidate(
            deps.as_ref(),
            env.clone(),
            &liquidator,  // Pass liquidator instead of info
            &config,
            msg,
            &account,
            // ... rest of parameters
        )?
        .add_message(
            ExecuteMsg::DoLiquidate {
                addr: account.id().to_string(),
                queue,
                payload,
                liquidator,  // Pass through
            }
            .call(&ca)?,
        ))
    }
}
```

**Modified execute_liquidate signature**:
```rust
pub fn execute_liquidate(
    deps: Deps,
    env: Env,
    liquidator: &Addr,  // Change from info: MessageInfo
    config: &Config,
    msg: LiquidateMsg,
    account: &CreditAccount,
    reply_id: u64,
) -> Result<Response, ContractError>
```

**Modified fee distribution**:
```rust
.add_message(BankMsg::Send {
    to_address: liquidator.to_string(),  // Use liquidator param
    amount: coins(liquidator_fee.u128(), denom.clone()),
})
```

## Proof of Concept

The following test demonstrates that liquidator fees are sent to the contract address instead of the liquidator (this would be added to the test suite):

```rust
#[test]
fn test_liquidator_fee_recipient() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let liquidator = app.api().addr_make("liquidator");
    
    // Setup accounts and positions as in existing tests
    let ctx = setup(&mut app, &owner);
    
    // Fund liquidator with some tokens
    app.send_tokens(
        owner.clone(),
        liquidator.clone(),
        &[coin(1000000000, USDC)],
    ).unwrap();
    
    // Create liquidatable position
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(10000000, BTC)],
    ).unwrap();
    
    ctx.ghost_credit
        .account_borrow(&mut app, &ctx.account, 1000000000, USDC)
        .unwrap();
    
    // Move price to make position liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::from_str("50000").unwrap()),
        ]);
    });
    
    // Record balances before liquidation
    let liquidator_balance_before = app.wrap().query_balance(&liquidator, USDC).unwrap();
    let contract_balance_before = app.wrap().query_balance(ctx.ghost_credit.addr(), USDC).unwrap();
    
    // Liquidator executes liquidation
    let result = app.execute_contract(
        liquidator.clone(),  // Liquidator is the sender
        ctx.ghost_credit.addr().clone(),
        &ExecuteMsg::Liquidate {
            addr: ctx.account.account.to_string(),
            msgs: vec![
                LiquidateMsg::Execute {
                    contract_addr: ctx.fin_btc_usdc.addr().to_string(),
                    msg: to_json_binary(&fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
                        to: None,
                        callback: None,
                    })).unwrap(),
                    funds: coins(1000000, BTC),
                },
                LiquidateMsg::Repay(USDC.to_string()),
            ],
        },
        &[],
    );
    
    // Check balances after liquidation
    let liquidator_balance_after = app.wrap().query_balance(&liquidator, USDC).unwrap();
    let contract_balance_after = app.wrap().query_balance(ctx.ghost_credit.addr(), USDC).unwrap();
    
    // BUG: Liquidator balance unchanged (no fee received)
    assert_eq!(liquidator_balance_before, liquidator_balance_after);
    
    // BUG: Contract received the fee instead
    assert!(contract_balance_after.amount > contract_balance_before.amount);
    
    // The fee that should have gone to liquidator went to contract
    let fee_to_contract = contract_balance_after.amount - contract_balance_before.amount;
    assert!(fee_to_contract > Uint128::zero());
}
```

**Notes**

This vulnerability is directly related to the security question about fee extraction during liquidations. While the question asks whether liquidators can extract fees with minimal effort by relying on preferences, the actual finding is more severe: liquidators cannot extract ANY fees regardless of effort due to the info.sender tracking bug. The event emission mentioned in the question (`event_execute_liquidate`) correctly captures the caller but this information is not propagated to the fee distribution logic, resulting in complete failure of the liquidation incentive mechanism.

### Citations

**File:** contracts/rujira-ghost-credit/README.md (L158-159)
```markdown

As a reward for solving and executing a liquidation, the account that calls the liquidation earns `config.fee_liquidator * repay` in a fee. This fee is paid only when the debt is repaid during a Liquidation, aligning incentives between the Protocol and the Liquidator. The Liquidator must plan a _route_ as a `Vec<LiquidationMsg>` in order exchange collateral for debt, and repay the debt.
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-76)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L89-98)
```rust
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
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L105-105)
```rust
            ensure_eq!(info.sender, ca, ContractError::Unauthorized {});
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L126-137)
```rust
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
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L308-311)
```rust
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
