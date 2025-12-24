# Audit Report

## Title
Unlimited Liquidation Preference Messages Enable Denial-of-Service on Position Liquidation Leading to Protocol Insolvency

## Summary
Account owners can set an unlimited number of liquidation preference messages that consume excessive gas when failing, preventing liquidators from completing liquidations of undercollateralized positions. This leads to accumulation of bad debt and protocol insolvency.

## Finding Description

The protocol allows account owners to set liquidation preference messages via `AccountMsg::SetPreferenceMsgs` to specify their preferred liquidation routes. These preferences are designed to fail gracefully without blocking liquidations, as evidenced by the silent error handling in the `reply()` function. [1](#0-0) 

However, there is no limit on the number of preference messages that can be set. [2](#0-1) 

During liquidation, preference messages are processed BEFORE liquidator-provided messages. [3](#0-2) 

The queue is constructed by reversing liquidator messages, reversing preference messages, and then appending preferences to the queue. Since `queue.pop()` is used to process messages from the end, preferences are executed first.

Each preference message, when implemented as `LiquidateMsg::Execute`, creates a SubMsg with `reply_always`. [4](#0-3) 

Even when these messages fail, they consume gas for:
1. SubMsg execution and contract call
2. Reply handler invocation
3. Recursive DoLiquidate message scheduling

**Attack Scenario:**

1. Attacker creates a credit account and borrows near the liquidation threshold
2. Before liquidation becomes necessary, attacker calls `SetPreferenceMsgs` with a large array (e.g., 500-1000) of `LiquidateMsg::Execute` messages that will always fail (calling a contract that reverts or doesn't exist)
3. Price movements cause the position to become undercollateralized (adjusted_ltv >= liquidation_threshold)
4. Liquidator attempts liquidation by calling `ExecuteMsg::Liquidate`
5. The transaction processes all failing preference messages first, each consuming significant gas
6. If total gas consumption exceeds the block gas limit (typically 50-100M gas in Cosmos chains) or practical transaction limits, the transaction fails before reaching the liquidator's messages
7. Position remains unliquidatable, accumulating bad debt

This breaks the **Safe Liquidation Outcomes** invariant, which states that liquidations must trigger when `adjusted_ltv >= liquidation_threshold`. The protocol's design comment acknowledges that "we can't have invalid messages blocking an account liquidation," but the implementation fails to prevent gas-based DoS. [5](#0-4) 

Note that while `LiquidationPreferenceOrder` has an explicit limit of 100 entries [6](#0-5) , no such limit exists for preference messages.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables direct protocol insolvency through the following impact chain:

1. **Prevention of Liquidations**: Undercollateralized positions cannot be liquidated when preference message gas consumption exceeds practical limits
2. **Bad Debt Accumulation**: As prices continue to move adversely, the position's debt grows relative to collateral value
3. **Systemic Risk**: Multiple exploited positions create cascading bad debt across the protocol
4. **Lender Losses**: Vault depositors cannot recover their full principal when borrowers default

The impact is systemic because:
- Any account owner can execute this attack at any time
- Once set, preferences persist until changed by the owner
- Liquidators have no mechanism to bypass or limit preference execution
- The attack succeeds even if liquidators submit with maximum gas, as block gas limits are finite

This directly contradicts the protocol's documented concern: "A particular attention should be given to anything that could result in liquidations not functioning as intended and leading to bad debt." [7](#0-6) 

## Likelihood Explanation

**Likelihood: HIGH**

The attack has high likelihood due to:

1. **Low Barrier to Entry**: Any account owner can set preference messages without restrictions
2. **No Preconditions**: Attack can be executed at account creation or any time before liquidation
3. **Persistent Effect**: Once set, malicious preferences remain active
4. **Economic Incentive**: Borrowers facing liquidation have strong incentive to delay/prevent it
5. **Simple Execution**: Attack requires only calling `SetPreferenceMsgs` with a large array
6. **No Cost**: Setting preferences is free (only requires ownership of the account)

The vulnerability is particularly likely to be exploited when:
- Markets are volatile and liquidations are imminent
- Borrowers want to avoid liquidation penalties
- Positions are significantly undercollateralized (giving borrower nothing to lose)

## Recommendation

Implement a hard limit on the number of preference messages that can be set, similar to the existing limit on preference order:

```rust
const MAX_PREFERENCE_MESSAGES: usize = 10;

pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    if msgs.len() > MAX_PREFERENCE_MESSAGES {
        return Err(ContractError::TooManyPreferences { 
            limit: MAX_PREFERENCE_MESSAGES,
            attempted: msgs.len() 
        });
    }
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

Update the handler to propagate errors: [8](#0-7) 

Change from:
```rust
AccountMsg::SetPreferenceMsgs(msgs) => {
    account.set_preference_msgs(msgs);
    Ok((vec![], vec![event_execute_account_set_preference_msgs()]))
}
```

To:
```rust
AccountMsg::SetPreferenceMsgs(msgs) => {
    account.set_preference_msgs(msgs)?;
    Ok((vec![], vec![event_execute_account_set_preference_msgs()]))
}
```

A limit of 10 preference messages should be sufficient for legitimate use cases (specifying 1-2 DEX routes per collateral type) while preventing gas DoS attacks.

## Proof of Concept

```rust
#[cfg(test)]
mod test_preference_dos {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coin, to_json_binary, Binary};
    use rujira_rs::ghost::credit::{AccountMsg, ExecuteMsg, LiquidateMsg};

    #[test]
    fn test_unlimited_preferences_dos() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Setup: Create account and make it liquidatable
        // (Setup code omitted for brevity - would instantiate contract,
        // create account, deposit collateral, borrow, trigger liquidation threshold)
        
        let owner = "account_owner";
        let account_addr = "credit_account_1";
        
        // Attack: Set 1000 preference messages that will fail
        let malicious_preferences: Vec<LiquidateMsg> = (0..1000)
            .map(|i| LiquidateMsg::Execute {
                contract_addr: format!("fake_contract_{}", i),
                msg: to_json_binary(&"invalid").unwrap(),
                funds: vec![],
            })
            .collect();
        
        // Account owner sets malicious preferences
        let msg = ExecuteMsg::Account {
            addr: account_addr.to_string(),
            msgs: vec![AccountMsg::SetPreferenceMsgs(malicious_preferences)],
        };
        
        let info = mock_info(owner, &[]);
        execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        
        // Attempt liquidation
        // In a real scenario, this would exceed gas limits
        let liquidator = "liquidator";
        let liquidate_msg = ExecuteMsg::Liquidate {
            addr: account_addr.to_string(),
            msgs: vec![
                LiquidateMsg::Execute {
                    contract_addr: "dex".to_string(),
                    msg: to_json_binary(&"swap").unwrap(),
                    funds: vec![coin(1000, "collateral")],
                },
                LiquidateMsg::Repay("debt_token".to_string()),
            ],
        };
        
        let info = mock_info(liquidator, &[]);
        
        // This would consume excessive gas processing 1000 failing preferences
        // before reaching the liquidator's 2 messages
        // In practice, this would exceed block gas limit and fail
        let result = execute(deps.as_mut(), env, info, liquidate_msg);
        
        // The liquidation would fail due to gas exhaustion,
        // leaving the undercollateralized position intact
        // This demonstrates the DoS vulnerability
    }
}
```

**Note:** The actual PoC would require the full test infrastructure with mock contracts, oracles, and vaults set up. The above demonstrates the attack pattern: an account owner sets many failing preferences that get processed before liquidator messages, consuming excessive gas and preventing liquidation completion.

---

## Notes

The vulnerability exists because the protocol correctly identified the risk of preference messages blocking liquidations (as evidenced by the silent error handling for REPLY_ID_PREFERENCE), but only addressed the error propagation aspect without considering gas consumption as a DoS vector. The lack of any limit on preference message count, combined with preferences being processed before liquidator messages, creates a direct path to making positions unliquidatable.

### Citations

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L246-249)
```rust
        AccountMsg::SetPreferenceMsgs(msgs) => {
            account.set_preference_msgs(msgs);
            Ok((vec![], vec![event_execute_account_set_preference_msgs()]))
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L344-346)
```rust
        (SubMsgResult::Err(err), REPLY_ID_PREFERENCE) => {
            // Don't block execution if this is a preferential step
            Ok(Response::default().add_event(event_execute_liquidate_preference_error(err)))
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L231-233)
```rust
    pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
        self.liquidation_preferences.messages = msgs
    }
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L254-258)
```rust
    /// These sub-messages are emitted as "Reply Always", and if the
    /// reply is an error state, we ignore the error.
    /// We can't have invalid messages blocking an account liquidation:
    /// User experience is the preference, but system solvency is the priority
    pub messages: Vec<LiquidateMsg>,
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L268-280)
```rust
pub struct LiquidationPreferenceOrder {
    map: BTreeMap<String, String>,
    limit: u8,
}

impl Default for LiquidationPreferenceOrder {
    fn default() -> Self {
        Self {
            map: Default::default(),
            limit: 100,
        }
    }
}
```

**File:** README.md (L78-78)
```markdown
A particular attention should be given to anything that could result in liquidations not functioning as intended and leading to bad debt.
```
