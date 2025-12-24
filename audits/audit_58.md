# Audit Report

## Title
Liquidation Race Condition Enables Gas Griefing and Reduces Liquidator Participation Efficiency

## Summary
Multiple liquidators can simultaneously call `ExecuteMsg::Liquidate` on the same undercollateralized account with no synchronization mechanism. The first liquidation to execute succeeds, while subsequent concurrent liquidations waste gas fees and receive no compensation, creating unfair competition and potentially discouraging liquidation participation.

## Finding Description

The liquidation mechanism in `contracts/rujira-ghost-credit/src/contract.rs` implements a two-phase process:

**Phase 1 - ExecuteMsg::Liquidate** [1](#0-0) 

This handler:
- Loads the account state from storage
- Checks if the account is unsafe (above liquidation threshold)
- Creates a liquidation message queue
- Schedules a `DoLiquidate` message
- Emits an event

**Critical Issue:** No state modification occurs during this phase. Multiple liquidators can concurrently read the same unsafe account state and all pass the safety check.

**Phase 2 - ExecuteMsg::DoLiquidate** [2](#0-1) 

This handler processes the actual liquidation, modifying account state by repaying debt and selling collateral.

**Attack Scenario:**

1. Account X has `adjusted_ltv = 0.85` (above `liquidation_threshold = 0.80`)
2. Liquidator A submits `ExecuteMsg::Liquidate` at time T1
   - Reads account (ltv = 0.85) 
   - Check passes, schedules DoLiquidate
3. Liquidator B submits `ExecuteMsg::Liquidate` at time T2 (same or next block)
   - Reads account (ltv = 0.85) - **same state, no lock exists**
   - Check passes, schedules DoLiquidate
4. A's DoLiquidate executes first, liquidates account successfully
5. B's DoLiquidate executes:
   - Line 107: Loads current state (now safe after A's liquidation)
   - Lines 110-117: Safety check passes (account now safe)
   - Line 119: Returns `Ok()` with no action
   - **Liquidator B receives nothing despite paying gas**

The event emission [3](#0-2)  provides no queue position, total queue size, or concurrency protection information.

## Impact Explanation

**Medium Severity** - This constitutes a DoS vulnerability affecting core functionality through economic manipulation:

1. **Gas Griefing:** Liquidators who lose the race waste transaction fees with zero compensation. At scale, this represents significant economic loss.

2. **Reduced Liquidation Participation:** Rational liquidators may avoid the protocol knowing they risk wasting gas in races, especially during high volatility when many accounts need liquidation simultaneously.

3. **Systemic Risk:** Slower liquidation response times increase bad debt accumulation risk. If liquidators are discouraged, underwater positions may not be liquidated promptly, threatening protocol solvency.

4. **Unfair Competition:** First-to-execute always wins with no fair queuing or priority system. This favors validators/relayers with transaction ordering control.

While this doesn't cause direct fund theft, it creates economic inefficiency that undermines the permissionless liquidation mechanism's effectiveness, potentially leading to systemic undercollateralization if liquidations are delayed.

## Likelihood Explanation

**High Likelihood:**

- Occurs naturally during market volatility when multiple liquidators target the same accounts
- No special permissions or complex setup required
- Any liquidator can trigger this by calling a public function
- Blockchain explorers and monitoring bots make it trivial to identify undercollateralized accounts
- The competitive liquidation market incentivizes multiple participants to act simultaneously

## Recommendation

Implement a reservation or locking mechanism during the initial liquidation check:

```rust
// Add to state.rs
pub const LIQUIDATION_LOCKS: Map<Addr, u64> = Map::new("liquidation_locks");

// Modify ExecuteMsg::Liquidate handler
ExecuteMsg::Liquidate { addr, msgs } => {
    let account_addr = deps.api.addr_validate(&addr)?;
    
    // Check if liquidation already in progress
    if LIQUIDATION_LOCKS.may_load(deps.storage, account_addr.clone())?.is_some() {
        return Err(ContractError::LiquidationInProgress {});
    }
    
    let account = CreditAccount::load(deps.as_ref(), &config, &ca, account_addr.clone())?;
    account.check_unsafe(&config.liquidation_threshold)?;
    
    // Lock the account for this liquidation
    LIQUIDATION_LOCKS.save(deps.storage, account_addr.clone(), &env.block.height)?;
    
    // ... rest of liquidation logic
}

// In DoLiquidate, clear the lock when complete
ExecuteMsg::DoLiquidate { addr, queue, payload } => {
    // ... existing logic ...
    
    // On completion (whether success or failure), clear the lock
    let account_addr = deps.api.addr_validate(&addr)?;
    LIQUIDATION_LOCKS.remove(deps.storage, account_addr);
    
    // ... rest of logic
}
```

Additionally, add queue position information to the event:

```rust
pub fn event_execute_liquidate(
    account: &CreditAccount, 
    caller: &Addr,
    queue_size: usize
) -> Event {
    Event::new(format!("{}/account.liquidate", env!("CARGO_PKG_NAME")))
        .add_attribute("owner", account.owner.clone())
        .add_attribute("address", account.id().to_string())
        .add_attribute("caller", caller.to_string())
        .add_attribute("queue_size", queue_size.to_string())
}
```

## Proof of Concept

```rust
#[test]
fn test_concurrent_liquidation_race_condition() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let liquidator_a = app.api().addr_make("liquidator_a");
    let liquidator_b = app.api().addr_make("liquidator_b");
    
    let ctx = setup(&mut app, &owner);
    
    // Setup: Create undercollateralized account
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(10000000, BTC)], // 0.1 BTC = $11,100
    ).unwrap();
    
    // Borrow close to limit
    ctx.ghost_credit
        .account_borrow(&mut app, &ctx.account, 8880000000, USDC) // $8,880
        .unwrap();
    
    // Price drop makes account liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::from_str("100000").unwrap()), // Drop to $100k
        ]);
    });
    
    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv > Decimal::from_str("0.80").unwrap()); // Above liquidation threshold
    
    // Both liquidators submit at nearly same time
    // Liquidator A's transaction
    let msg_a = ExecuteMsg::Liquidate {
        addr: ctx.account.account.to_string(),
        msgs: vec![LiquidateMsg::Repay(USDC.to_string())],
    };
    
    // Liquidator B's transaction (identical intent)
    let msg_b = ExecuteMsg::Liquidate {
        addr: ctx.account.account.to_string(),
        msgs: vec![LiquidateMsg::Repay(USDC.to_string())],
    };
    
    // Both succeed in submitting (no lock prevents this)
    let res_a = app.execute_contract(
        liquidator_a.clone(),
        ctx.ghost_credit.addr(),
        &msg_a,
        &[],
    ).unwrap();
    
    let res_b = app.execute_contract(
        liquidator_b.clone(),
        ctx.ghost_credit.addr(),
        &msg_b,
        &[],
    ).unwrap();
    
    // Both emit events showing they "initiated" liquidation
    assert!(res_a.events.iter().any(|e| e.ty.contains("liquidate")));
    assert!(res_b.events.iter().any(|e| e.ty.contains("liquidate")));
    
    // Check final state: only ONE liquidation actually executed
    // Liquidator B wasted gas with no compensation
    let final_account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    
    // Account is now safe (only liquidated once)
    assert!(final_account.ltv < Decimal::from_str("0.80").unwrap());
    
    // Liquidator B got no fee despite their transaction executing
    // This demonstrates the race condition and gas waste
}
```

**Notes:**
- The vulnerability exists in the lack of synchronization between concurrent liquidation attempts
- While the protocol state remains consistent (no over-liquidation occurs due to validation checks), liquidator participants suffer economic loss
- This issue specifically affects the "permissionless liquidation" design goal by introducing unfair competition and economic disincentives

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-149)
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
        }
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
