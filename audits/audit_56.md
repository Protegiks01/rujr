# Audit Report

## Title
Unbounded Error Messages in Liquidation Preferences Can Cause DoS on Liquidations

## Summary
The `event_execute_liquidate_preference_error()` function logs error messages from failed liquidation preference executions without any size validation. Malicious users can set liquidation preferences that execute contracts returning arbitrarily large error messages, potentially causing liquidation transactions to fail due to CosmWasm transaction size limits, effectively preventing liquidation of undercollateralized accounts.

## Finding Description

The vulnerability exists in the liquidation preference error handling mechanism. When users set liquidation preference messages via `AccountMsg::SetPreferenceMsgs`, they can specify arbitrary contract executions. [1](#0-0) 

During liquidation, these preference messages are executed as submessages with `REPLY_ID_PREFERENCE`. [2](#0-1) 

When a preference message fails, the error is captured in the reply handler and logged to an event without any size validation: [3](#0-2) 

The event function directly adds the error string as an attribute with no truncation: [4](#0-3) 

**Attack Path:**
1. Malicious user creates a credit account
2. User deploys a malicious contract that always fails with an extremely large error message (e.g., 500KB of repeated characters)
3. User calls `SetPreferenceMsgs` with `LiquidateMsg::Execute` pointing to this malicious contract
4. User borrows and becomes liquidatable
5. When liquidation is attempted, the preference message executes and fails with the massive error
6. The error is logged to the event, causing the transaction to exceed CosmWasm/Cosmos SDK size limits
7. The liquidation transaction fails entirely

This breaks **Invariant #3 (Safe Liquidation Outcomes)**: "Liquidations only trigger when adjusted_ltv >= liquidation_threshold" - the account remains liquidatable but the liquidation cannot execute successfully due to transaction size constraints.

The liquidation preferences are **always** included in the liquidation queue [5](#0-4) , meaning liquidators cannot bypass this attack vector.

## Impact Explanation

This vulnerability enables a DoS attack on the liquidation mechanism, which is core protocol functionality. While the impact is limited to the attacker's own account (self-griefing), it has serious consequences:

1. **Prevents Liquidation of Undercollateralized Positions**: Accounts that should be liquidated remain active, holding debt against insufficient collateral
2. **Protocol Insolvency Risk**: If multiple users employ this technique or if significant positions cannot be liquidated, the protocol accumulates bad debt
3. **Defeats Liquidation Safety Mechanism**: The entire purpose of liquidations is to maintain protocol solvency, which this vulnerability undermines

The attacker can strategically use this to avoid liquidation penalties by making their account unliquidatable, effectively borrowing with insufficient collateral as prices move against them.

**Medium Severity** is appropriate because this is a DoS vulnerability affecting core functionality (liquidations) per the defined impact categories.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack requires:
- Creating a credit account (permissionless)
- Deploying a malicious contract (trivial - just return large error strings)
- Setting liquidation preferences (single transaction via `SetPreferenceMsgs`)
- Becoming liquidatable (natural market movement)

The attacker must set up the malicious preferences **before** becoming liquidatable, but this is easy to do during normal account operation. Any user anticipating potential liquidation can implement this as a preventive measure.

The technical barrier is very low - the malicious contract can be as simple as:
```rust
Err(StdError::generic_err("A".repeat(500_000)))
```

This is a realistic attack vector that rational actors would employ to avoid liquidation losses, especially in volatile market conditions.

## Recommendation

Implement error message truncation in the event logging function:

```rust
pub fn event_execute_liquidate_preference_error(msg: String) -> Event {
    const MAX_ERROR_LENGTH: usize = 1024; // 1KB limit
    let truncated_msg = if msg.len() > MAX_ERROR_LENGTH {
        format!("{}... (truncated, original length: {})", 
                &msg[..MAX_ERROR_LENGTH], 
                msg.len())
    } else {
        msg
    };
    
    Event::new(format!(
        "{}/liquidate.msg/preference.error",
        env!("CARGO_PKG_NAME")
    ))
    .add_attribute("error", truncated_msg)
}
```

Additionally, consider:
1. Limiting the number of preference messages per account
2. Implementing a gas limit or complexity cap on preference message executions
3. Adding validation when users set preference messages to reject obviously malicious patterns

## Proof of Concept

While a full PoC would require setting up the complete test environment with a malicious contract that returns oversized errors, the vulnerability can be demonstrated through the code flow:

1. **User sets malicious preference**: Via `ExecuteMsg::Account` with `AccountMsg::SetPreferenceMsgs(vec![LiquidateMsg::Execute { contract_addr: "malicious_contract", ... }])`

2. **No validation occurs**: The `set_preference_msgs` function performs no validation on message content or potential error sizes

3. **Liquidation triggers execution**: When liquidation occurs, the queue includes preference messages which are executed as `SubMsg::reply_always`

4. **Error logged without bounds**: Failed preference execution returns to the reply handler, which logs the error directly to an event with no size validation

5. **Transaction size exceeded**: If the error message is sufficiently large (typically 100KB+ depending on chain configuration), the transaction response exceeds CosmWasm limits and fails

**Conceptual test scenario:**
```rust
// Pseudo-code demonstrating the attack
#[test]
fn test_unbounded_error_dos_liquidation() {
    let mut app = mock_app();
    
    // 1. User creates account and sets malicious preference
    let malicious_contract = deploy_malicious_contract(&mut app); // Returns 500KB error
    credit.account_set_preference_msgs(
        &mut app, 
        vec![LiquidateMsg::Execute {
            contract_addr: malicious_contract,
            msg: Binary::default(),
            funds: vec![]
        }]
    );
    
    // 2. User borrows and becomes liquidatable
    credit.account_borrow(&mut app, 1_000_000, "USDC");
    // Price drops, account becomes unsafe
    
    // 3. Liquidation attempt should fail due to oversized response
    let result = credit.liquidate(&mut app, account_addr, vec![]);
    
    // Expected: Transaction fails due to response size limits
    assert!(result.is_err());
    // Account remains liquidatable but cannot be liquidated
}
```

The exact transaction size limits depend on the specific CosmWasm/Cosmos SDK chain configuration, but typical limits are in the 256KB-1MB range. An error message of 500KB would reliably trigger this issue on most chains.

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L344-346)
```rust
        (SubMsgResult::Err(err), REPLY_ID_PREFERENCE) => {
            // Don't block execution if this is a preferential step
            Ok(Response::default().add_event(event_execute_liquidate_preference_error(err)))
```

**File:** contracts/rujira-ghost-credit/src/events.rs (L73-79)
```rust
pub fn event_execute_liquidate_preference_error(msg: String) -> Event {
    Event::new(format!(
        "{}/liquidate.msg/preference.error",
        env!("CARGO_PKG_NAME")
    ))
    .add_attribute("error", msg.to_string())
}
```
