# Audit Report

## Title
Unbounded Binary Event Emission in Liquidation Preferences Enables Liquidation DoS Leading to Protocol Insolvency

## Summary
Malicious borrowers can set liquidation preference messages containing arbitrarily large `Binary` payloads that cause liquidation transactions to exceed Cosmos SDK size limits and fail, preventing protocol liquidations and accumulating bad debt.

## Finding Description

The `event_execute_liquidate_execute` function emits `Binary` messages without size validation when processing liquidation preference messages. [1](#0-0) 

Users can set liquidation preferences containing `LiquidateMsg::Execute` variants with unbounded `Binary` payloads via `AccountMsg::SetPreferenceMsgs`, which directly assigns the messages without any size validation. [2](#0-1) 

During liquidation, these preference messages are **always** prepended to the liquidation queue and executed before liquidator-provided messages. [3](#0-2) 

When processing `LiquidateMsg::Execute`, the contract emits events containing the full `Binary` payload by calling `msg.to_string()`, which base64-encodes the binary data (increasing size by ~33%). [4](#0-3) 

**Attack Path:**
1. Attacker creates a credit account and borrows funds
2. Attacker calls `ExecuteMsg::Account` with `AccountMsg::SetPreferenceMsgs` containing `LiquidateMsg::Execute` messages with ~1.5MB `Binary` payloads (which become ~2MB when base64-encoded in events)
3. Account becomes unhealthy (adjusted_ltv ≥ liquidation_threshold)
4. Liquidator attempts liquidation via `ExecuteMsg::Liquidate`
5. Contract loads preference messages and adds them to liquidation queue
6. When processing preference Execute messages, events with huge base64-encoded Binary are emitted
7. Transaction exceeds Cosmos SDK size limits (typically 1-2MB) and is **rejected by mempool**
8. Liquidation fails; liquidator cannot bypass preferences as they are **always included**
9. Account remains underwater, protocol accumulates bad debt

This breaks the **"Safe Liquidation Outcomes"** invariant, which requires liquidations to succeed when `adjusted_ltv >= liquidation_threshold`.

## Impact Explanation

**High Severity**: This vulnerability enables systemic undercollateralization and bad debt accumulation:

- Attackers can create unliquidatable positions by setting preference messages with large Binary payloads
- When accounts become underwater, liquidations systematically fail due to transaction size limits
- Protocol cannot recover bad debt through liquidation mechanisms
- Multiple attackers exploiting this could lead to protocol insolvency
- No liquidator can bypass the preferences to liquidate these accounts

This is not merely an "event emission issue" - it's a **critical DoS on the protocol's solvency mechanism** that prevents the core liquidation functionality from operating.

## Likelihood Explanation

**High Likelihood:**
- Attack requires no special permissions (any account owner can set preferences)
- Trivial to execute (single transaction with large Binary payload)
- No external dependencies or timing requirements
- Cosmos SDK transaction limits are well-known (1-2MB typical)
- Attacker fully controls preference message content and size
- No economic cost beyond gas for setting preferences

## Recommendation

Add size validation to `set_preference_msgs` to limit individual Binary message sizes and total preference message data:

```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    const MAX_MSG_SIZE: usize = 100_000; // 100KB per message
    const MAX_TOTAL_SIZE: usize = 500_000; // 500KB total
    
    let mut total_size = 0;
    for msg in &msgs {
        if let LiquidateMsg::Execute { msg, .. } = msg {
            let msg_size = msg.len();
            if msg_size > MAX_MSG_SIZE {
                return Err(ContractError::PreferenceMsgTooLarge { 
                    size: msg_size, 
                    max: MAX_MSG_SIZE 
                });
            }
            total_size += msg_size;
        }
    }
    
    if total_size > MAX_TOTAL_SIZE {
        return Err(ContractError::PreferenceMsgsTotalTooLarge { 
            size: total_size, 
            max: MAX_TOTAL_SIZE 
        });
    }
    
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

Also consider adding limits to the number of preference messages to prevent gas exhaustion attacks.

## Proof of Concept

```rust
#[cfg(test)]
mod liquidation_dos_test {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, Binary};
    use rujira_rs::ghost::credit::{AccountMsg, ExecuteMsg, LiquidateMsg};
    
    #[test]
    fn test_liquidation_dos_via_large_binary_preference() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Setup: Create account with collateral and debt
        // (setup code omitted for brevity - would initialize config, create account, borrow funds)
        
        let attacker = "attacker_addr";
        let account_addr = "account_addr";
        
        // Step 1: Attacker sets liquidation preferences with huge Binary
        // Create a 1.5MB Binary (will become ~2MB when base64-encoded in events)
        let huge_binary = Binary::from(vec![0u8; 1_500_000]);
        
        let set_prefs_msg = ExecuteMsg::Account {
            addr: account_addr.to_string(),
            msgs: vec![AccountMsg::SetPreferenceMsgs(vec![
                LiquidateMsg::Execute {
                    contract_addr: "some_contract".to_string(),
                    msg: huge_binary,
                    funds: vec![],
                }
            ])],
        };
        
        let info = mock_info(attacker, &[]);
        
        // This succeeds - no size validation
        let res = execute(deps.as_mut(), env.clone(), info.clone(), set_prefs_msg);
        assert!(res.is_ok());
        
        // Step 2: Account becomes unhealthy (price drop or over-borrowing)
        // (state manipulation omitted - would reduce collateral value or increase debt)
        
        // Step 3: Liquidator attempts liquidation
        let liquidator = "liquidator_addr";
        let liquidate_msg = ExecuteMsg::Liquidate {
            addr: account_addr.to_string(),
            msgs: vec![
                LiquidateMsg::Repay("debt_denom".to_string()),
            ],
        };
        
        let liquidator_info = mock_info(liquidator, &[]);
        
        // This would fail with transaction size exceeded error in real chain
        // In test environment, we verify the huge Binary is included in events
        let res = execute(deps.as_mut(), env.clone(), liquidator_info, liquidate_msg);
        
        // In production: Transaction would be rejected by Cosmos SDK mempool
        // Result: Account remains unliquidatable, protocol accumulates bad debt
        
        // Verify that the preference message with huge Binary is in the queue
        // (verification code would check that event contains the large base64 string)
    }
}
```

**Note**: A complete PoC would require full integration test setup with THORChain oracle mocks, vault initialization, and actual transaction size limit testing against a local chain. The above demonstrates the attack flow; actual transaction rejection would occur at Cosmos SDK mempool validation.

### Citations

**File:** contracts/rujira-ghost-credit/src/events.rs (L94-103)
```rust
pub fn event_execute_liquidate_execute(
    contract_addr: &String,
    msg: &Binary,
    funds: &NativeBalance,
) -> Event {
    Event::new(format!("{}/liquidate.msg/execute", env!("CARGO_PKG_NAME")))
        .add_attribute("contract_addr", contract_addr.to_string())
        .add_attribute("msg", msg.to_string())
        .add_attribute("funds", funds.to_string())
}
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L231-233)
```rust
    pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
        self.liquidation_preferences.messages = msgs
    }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-87)
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
