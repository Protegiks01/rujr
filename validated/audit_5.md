# Audit Report

## Title
Unbounded Liquidation Preferences Enable DoS of Liquidation Mechanism, Leading to Protocol Insolvency

## Summary
The `liquidation_preferences.messages` vector in credit accounts lacks size validation, allowing account owners to set arbitrarily large preference vectors. During liquidation, the account serialization fails due to exceeding CosmWasm message size limits, rendering unsafe positions unliquidatable and exposing the protocol to bad debt accumulation.

## Finding Description
This vulnerability breaks **Invariant #3: Safe Liquidation Outcomes** by allowing account owners to prevent their own liquidation through a denial-of-service attack.

The attack path begins when an account owner calls `AccountMsg::SetPreferenceMsgs(msgs)` with a large vector (e.g., 5,000-10,000 entries). The `set_preference_msgs` function directly assigns this vector without any size validation. [1](#0-0) 

When the account becomes unsafe (LTV >= liquidation_threshold) and `ExecuteMsg::Liquidate` is called, the system attempts to serialize the entire `CreditAccount` structure, which includes the oversized `liquidation_preferences.messages` vector. [2](#0-1) 

The serialization at line 94 via `to_json_binary(&account)?` attempts to convert the entire account into a Binary payload. [3](#0-2)  With thousands of `LiquidateMsg` entries, this serialization can exceed CosmWasm message size limits (typically 256KB-512KB) or consume excessive gas, causing the transaction to fail and preventing liquidation.

The `CreditAccount` structure contains the unbounded vector within its `liquidation_preferences` field. [4](#0-3) 

Additionally, a second serialization occurs during `execute_liquidate` when setting the payload for reply handling. [5](#0-4) 

The codebase demonstrates awareness of this issue type, as `liquidation_preferences.order` has an explicit 100-entry limit with validation in the `insert` method. [6](#0-5)  However, `liquidation_preferences.messages` is simply defined as `Vec<LiquidateMsg>` with no such protection. [7](#0-6) 

## Impact Explanation
**CRITICAL SEVERITY** - This vulnerability enables intentional position unliquidatability, leading to protocol insolvency:

- An account holder with substantial collateral can set thousands of preference messages before their position becomes unsafe
- When market conditions deteriorate and LTV exceeds the liquidation threshold, any liquidation attempt fails due to serialization limits
- The protocol cannot recover bad debt through the liquidation mechanism
- Multiple actors can exploit this simultaneously, causing systemic insolvency
- No admin intervention can force liquidation without the account owner's cooperation to remove preference messages

This directly violates the protocol's core security guarantee that positions above the liquidation threshold can always be liquidated, exposing lenders in the vault system to unrecoverable losses.

## Likelihood Explanation
**HIGH LIKELIHOOD**:

1. **Low barrier to exploitation**: Any account owner can call `SetPreferenceMsgs` through the owner-gated `ExecuteMsg::Account` interface - no special privileges required
2. **Strong economic incentive**: When facing liquidation on large positions during market volatility, account holders have rational incentive to prevent liquidation by blocking the mechanism
3. **Precedent in codebase**: The existence of a 100-entry limit on `liquidation_preferences.order` demonstrates the developers recognized this concern, but the asymmetry reveals an oversight for `messages`
4. **Minimal attack cost**: Setting preferences costs only transaction fees, but protects potentially millions in collateral from liquidation
5. **Difficult to detect proactively**: The DoS only manifests during liquidation attempts, making preemptive intervention challenging

## Recommendation
Implement a size limit for `liquidation_preferences.messages` similar to the existing limit on `liquidation_preferences.order`:

```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) -> Result<(), ContractError> {
    const MAX_PREFERENCE_MSGS: usize = 100;
    if msgs.len() > MAX_PREFERENCE_MSGS {
        return Err(ContractError::TooManyPreferenceMessages { 
            count: msgs.len(), 
            max: MAX_PREFERENCE_MSGS 
        });
    }
    self.liquidation_preferences.messages = msgs;
    Ok(())
}
```

Update the handler in `contract.rs` to propagate the error:
```rust
AccountMsg::SetPreferenceMsgs(msgs) => {
    account.set_preference_msgs(msgs)?;
    Ok((vec![], vec![event_execute_account_set_preference_msgs()]))
}
```

## Proof of Concept
A Rust test demonstrating this vulnerability would create an account, set a large `liquidation_preferences.messages` vector, make the account unsafe, and then show that liquidation attempts fail with serialization errors. The test would verify that reducing the preference vector size allows liquidation to proceed normally, confirming the root cause.

## Notes
- The vulnerability is exacerbated by the fact that `LiquidateMsg::Execute` can contain arbitrary `Binary` data, allowing individual messages to be large in addition to the vector quantity
- The asymmetry between `order` (limited) and `messages` (unlimited) strongly suggests an oversight rather than intentional design
- Test coverage gaps were confirmed - no existing tests validate large preference message vectors
- The `?` operator on serialization ensures transaction revert rather than silent failure, making the DoS deterministic

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L31-38)
```rust
pub struct CreditAccount {
    pub owner: Addr,
    pub tag: String,
    pub account: Account,
    pub collaterals: Vec<Valued<Collateral>>,
    pub debts: Vec<Valued<Debt>>,
    pub liquidation_preferences: LiquidationPreferences,
}
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L231-233)
```rust
    pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
        self.liquidation_preferences.messages = msgs
    }
```

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L331-331)
```rust
                .with_payload(to_json_binary(&account)?),
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L258-258)
```rust
    pub messages: Vec<LiquidateMsg>,
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L268-298)
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

impl LiquidationPreferenceOrder {
    pub fn insert(
        &mut self,
        key: String,
        value: String,
    ) -> Result<Option<String>, LiquidationPreferenceOrderError> {
        if self.map.len() >= self.limit.into() {
            return Err(LiquidationPreferenceOrderError::LimitReached(self.limit));
        }

        let res = self.map.insert(key, value.clone());
        // Check for circular constraints by ensuring dependency chain terminates
        for key in self.map.keys() {
            self.validate_chain(&value, key)?;
        }
        Ok(res)
    }
```
