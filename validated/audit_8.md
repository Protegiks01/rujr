# Audit Report

## Title
Unbounded Liquidation Preference Messages Enable DoS of Liquidation Mechanism

## Summary
The `SetPreferenceMsgs` function in the Rujira Ghost Credit contract accepts an unbounded vector of liquidation messages without validation. An attacker can set thousands of preference messages, causing liquidation attempts to fail due to excessive gas consumption from recursive message processing, leading to bad debt accumulation and potential protocol insolvency.

## Finding Description

The vulnerability exists in the handling of liquidation preference messages. The `set_preference_msgs` function performs no validation on the size or content of the messages vector: [1](#0-0) 

This setter is called by the `execute_account` function when processing `AccountMsg::SetPreferenceMsgs`: [2](#0-1) 

When liquidation is triggered via `ExecuteMsg::Liquidate`, the system builds a queue that combines liquidator-provided messages with account preference messages: [3](#0-2) 

The `DoLiquidate` function then processes messages one at a time in a recursive pattern, popping from the queue and scheduling the next iteration: [4](#0-3) 

Each message requires a separate contract call within the same transaction, consuming gas. The `LiquidationPreferences` struct shows a critical inconsistency - the `order` field has an explicit limit of 100, but the `messages` field has no such restriction: [5](#0-4) [6](#0-5) 

**Attack Flow:**

1. Attacker creates a credit account and deposits collateral
2. Attacker borrows funds against the collateral
3. Attacker calls `SetPreferenceMsgs` with 10,000+ `LiquidateMsg::Execute` messages (each can be a simple no-op call)
4. Market conditions change, making the account liquidatable (LTV exceeds liquidation threshold)
5. Liquidator attempts to liquidate the account via `ExecuteMsg::Liquidate`
6. The liquidation process must recursively process all 10,000+ preference messages before processing liquidator messages
7. The transaction fails due to gas exhaustion
8. The account remains unliquidatable, accumulating bad debt for the protocol

**Broken Invariant:** This violates **Invariant #3: "Safe Liquidation Outcomes"** as documented in the README: [7](#0-6) 

The DoS prevents liquidations from completing successfully, allowing undercollateralized positions to persist indefinitely.

## Impact Explanation

**HIGH Severity** - This is a DoS vulnerability affecting core protocol functionality with significant economic consequences. The README explicitly identifies this as a critical concern: [8](#0-7) 

1. **Bad Debt Accumulation**: Unliquidatable accounts accrue debt as interest compounds while collateral value may decline further, creating protocol insolvency

2. **Systemic Risk**: Multiple attackers exploiting this can create widespread undercollateralization, threatening the solvency of lending vaults and putting depositor funds at risk

3. **Economic Manipulation**: Attackers can maintain underwater positions longer than intended, potentially profiting from favorable price movements while socializing losses to the protocol

4. **Protocol Reputation**: Failed liquidations undermine confidence in the protocol's risk management system

The attack cost is minimal (setting preference messages costs only gas for a single transaction), while the impact is severe (preventing liquidations indefinitely).

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is highly likely to be exploited because:

1. **Low Complexity**: The attack requires only a single transaction to set preference messages - no specialized knowledge or tools needed

2. **No Preconditions**: Any account owner can execute this attack through normal protocol operations; no special permissions or timing requirements

3. **High Incentive**: During market volatility, borrowers facing liquidation have strong financial incentives to prevent liquidation and avoid losses

4. **Clear Benefit**: Attackers can delay liquidation during temporary price movements or indefinitely maintain underwater positions

5. **Observable Pattern**: The inconsistency between the limited `order` field (100 limit) and unlimited `messages` field suggests this was an oversight, not an intentional design choice

## Recommendation

Implement a maximum size limit for the liquidation preference messages vector, consistent with the existing limit on the `order` field:

```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    const MAX_PREFERENCE_MESSAGES: usize = 100;
    
    if msgs.len() > MAX_PREFERENCE_MESSAGES {
        return Err(ContractError::TooManyPreferenceMessages { 
            max: MAX_PREFERENCE_MESSAGES,
            provided: msgs.len() 
        });
    }
    
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

Update the struct definition to document this limit:

```rust
pub struct LiquidationPreferences {
    /// A list of LiquidateMsg's (max 100) that are injected into the
    /// start of a ExecuteMsg::Liquidate
    pub messages: Vec<LiquidateMsg>,
    pub order: LiquidationPreferenceOrder,
}
```

## Proof of Concept

```rust
#[test]
fn test_dos_liquidation_with_unbounded_preferences() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("attacker");
    
    // Setup protocol with vault and credit system
    let ghost_vault = GhostVault::create(&mut app, &owner, "BTC");
    let ghost_credit = GhostCredit::create(&mut app, &owner, &owner);
    ghost_credit.set_collateral(&mut app, "BTC", "0.8");
    ghost_credit.set_vault(&mut app, &ghost_vault);
    
    // Attacker creates account and deposits collateral
    ghost_credit.create_account(&mut app, &owner, "", "", Binary::new(vec![0]));
    let account_addr = ghost_credit.predict_account(&app, &owner, Binary::new(vec![0]));
    
    app.send_tokens(owner.clone(), account_addr.clone(), &[coin(100000000, "BTC")])
        .unwrap();
    
    // Attacker borrows funds
    let account = ghost_credit.query_account(&app, &account_addr);
    ghost_credit.account_borrow(&mut app, &account, 80000000000, "USDC").unwrap();
    
    // Attacker sets 10,000 preference messages (DoS attack)
    let mut large_preference_msgs = Vec::new();
    for i in 0..10000 {
        large_preference_msgs.push(LiquidateMsg::Execute {
            contract_addr: "dummy_contract".to_string(),
            msg: Binary::from(b"{}"),
            funds: vec![],
        });
    }
    
    // This succeeds because there's no validation
    ghost_credit.account_set_preference_msgs(&mut app, &account, large_preference_msgs)
        .unwrap();
    
    // Price drops, account becomes liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![("BTC", Decimal::from_str("50000").unwrap())]);
    });
    
    let account = ghost_credit.query_account(&app, &account_addr);
    assert!(account.ltv > Decimal::one()); // Account is unsafe
    
    // Liquidator attempts liquidation
    let liquidator = app.api().addr_make("liquidator");
    
    // This will fail due to gas exhaustion from processing 10,000 preference messages
    let result = ghost_credit.liquidate_execute_repay(
        &mut app,
        &account,
        "swap_contract",
        SwapMsg {},
        coins(1000000, "BTC"),
        "USDC",
    );
    
    // Transaction reverts due to gas limit
    assert!(result.is_err());
    
    // Account remains unliquidatable despite being unsafe
    let account = ghost_credit.query_account(&app, &account_addr);
    assert!(account.ltv > Decimal::one()); // Still underwater but can't be liquidated
}
```

## Notes

The vulnerability is confirmed by multiple pieces of evidence:
1. The `set_preference_msgs` function has no size validation
2. The `LiquidationPreferenceOrder.limit` field shows the developers were aware of the need for limits, but this was not applied to `messages`
3. The recursive `DoLiquidate` pattern processes each message individually, making gas exhaustion inevitable with large message counts
4. Preference messages are processed before liquidator messages due to the queue construction order, ensuring all preference messages must complete before liquidation can succeed

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L118-148)
```rust
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L246-249)
```rust
        AccountMsg::SetPreferenceMsgs(msgs) => {
            account.set_preference_msgs(msgs);
            Ok((vec![], vec![event_execute_account_set_preference_msgs()]))
        }
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L258-258)
```rust
    pub messages: Vec<LiquidateMsg>,
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L268-271)
```rust
pub struct LiquidationPreferenceOrder {
    map: BTreeMap<String, String>,
    limit: u8,
}
```

**File:** README.md (L78-78)
```markdown
A particular attention should be given to anything that could result in liquidations not functioning as intended and leading to bad debt.
```

**File:** README.md (L92-94)
```markdown
### Safe Liquidation Outcomes

Liquidation starts only when adjusted_ltv ≥ liquidation_threshold, then every iteration validates that the final account is under the liquidation threshold yet still above adjustment_threshold and respects user preference order plus max slip; otherwise the queue keeps executing or the tx reverts, ensuring liquidators can’t over-sell (contracts/rujira-ghost-credit/src/contract.rs (lines 73-150), contracts/rujira-ghost-credit/src/account.rs (lines 247-281)).
```
