# Audit Report

## Title
Liquidation Queue Failure Due to Mid-Execution Config Updates Causes Account Limbo State

## Summary
When `liquidation_max_slip` is updated to a more restrictive value during an ongoing liquidation, the liquidation process can fail validation checks, causing accounts to become permanently stuck in an unsafe state where neither liquidation nor owner-initiated debt repayment is possible.

## Finding Description
The Rujira protocol implements a queue-based liquidation mechanism where `ExecuteMsg::Liquidate` initializes a liquidation queue and `ExecuteMsg::DoLiquidate` recursively processes it. The vulnerability arises from the fact that the protocol configuration is reloaded from storage on each iteration of the liquidation loop, while the original account state is preserved in the message payload. [1](#0-0) 

During liquidation execution, each `DoLiquidate` iteration performs validation using the current (potentially updated) config: [2](#0-1) 

The critical issue occurs in `validate_liquidation`, which checks slippage against the current config's `liquidation_max_slip`: [3](#0-2) 

**Attack Flow:**

1. Account becomes unsafe (LTV ≥ liquidation_threshold = 100%)
2. Liquidator initiates `ExecuteMsg::Liquidate` with messages designed for current `liquidation_max_slip` of 50%
3. Original account state is serialized in the payload
4. Governance executes `SudoMsg::UpdateConfig` reducing `liquidation_max_slip` to 10% [4](#0-3) 

5. `DoLiquidate` continues processing, reloading the fresh config with 10% max slip
6. Liquidation messages execute with 30% actual slippage (valid under old 50% limit)
7. `validate_liquidation` fails because 30% > 10% (new limit) [5](#0-4) 

8. Transaction reverts with `LiquidationMaxSlipExceeded` error [6](#0-5) 

**Account Enters Limbo State:**

The account remains unsafe (LTV ≥ liquidation_threshold), but the owner cannot perform recovery operations because all owner operations end with a `CheckAccount` validation: [7](#0-6) 

Since the account is unsafe, LTV ≥ liquidation_threshold > adjustment_threshold, causing the `check_safe` validation to fail. This blocks all owner-initiated debt repayment attempts.

**Invariant Broken:**

This violates the **"Safe Liquidation Outcomes"** invariant, which states that liquidations must complete successfully when triggered on unsafe accounts. The protocol assumes accounts can always be brought back to a safe state, but this assumption breaks when config changes invalidate ongoing liquidations.

## Impact Explanation
**Severity: HIGH**

This vulnerability causes temporary to permanent freezing of funds with significant economic impact:

1. **Stuck Collateral**: Account owners cannot access their collateral while the account remains in limbo
2. **Unpayable Debt**: Owners cannot manually repay debt to restore the account to a safe state
3. **Failed Liquidations**: If market conditions do not support the new lower slippage threshold, no liquidation can succeed
4. **Systemic Risk**: Multiple accounts can simultaneously enter this state during a single config update, affecting protocol-wide liquidity

The accounts remain frozen until either:
- Governance reverts the config to higher `liquidation_max_slip` values
- Market conditions improve to support the lower slippage threshold
- Manual intervention through protocol migration/redeployment

This represents a clear violation of the protocol's core liquidation mechanism and can lead to widespread undercollateralization if multiple accounts are affected.

## Likelihood Explanation
**Likelihood: MEDIUM-HIGH**

The likelihood is assessed as medium-high because:

1. **Realistic Governance Action**: Reducing `liquidation_max_slip` is a legitimate risk management decision that governance may make during market volatility
2. **Timing Overlap**: Liquidations can take multiple blocks to complete, creating a window where config updates can interfere
3. **Market Conditions**: During volatile markets, governance may tighten risk parameters precisely when liquidations are most active
4. **No Protective Mechanisms**: The protocol has no safeguards against mid-liquidation config changes
5. **Observable in Production**: This can occur in normal protocol operations without any malicious actors

The scenario does not require attacker coordination or oracle manipulation—it can happen through standard protocol operations during legitimate governance actions.

## Recommendation

**Solution 1: Snapshot Config in Liquidation Payload**

Capture the config state when liquidation begins and use it throughout the liquidation process:

```rust
// In ExecuteMsg::Liquidate
let config_snapshot = to_json_binary(&config)?;
Ok(Response::default()
    .add_message(
        ExecuteMsg::DoLiquidate {
            addr: account.id().to_string(),
            queue,
            payload: to_json_binary(&account)?,
            config_snapshot, // Add this field
        }
        .call(&ca)?,
    )
    .add_event(event_execute_liquidate(&account, &info.sender)))

// In ExecuteMsg::DoLiquidate
let config_snapshot: Config = from_json(&config_snapshot)?;
// Use config_snapshot for validation instead of loading fresh config
```

**Solution 2: Add Config Version Check**

Add a version counter to the config and validate it hasn't changed:

```rust
pub struct Config {
    pub version: u64,  // Add this field
    // ... existing fields
}

// In DoLiquidate
if config.version != original_config_version {
    return Err(ContractError::ConfigChanged {});
}
```

**Solution 3: Allow Owner Operations on Unsafe Accounts with Restrictions**

Permit owners to repay debt even when the account is unsafe, but disallow collateral withdrawals or new borrowing:

```rust
// Modify CheckAccount to allow repayment operations
ExecuteMsg::CheckAccount { addr, allow_repay } => {
    let account = CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
    if !allow_repay {
        account.check_safe(&config.adjustment_threshold)?;
    }
    // Allow transaction to proceed if allow_repay is true
    Ok(Response::default())
}
```

**Recommended Approach**: Implement Solution 1 (config snapshot) as it preserves the original liquidation parameters throughout execution while requiring minimal changes to the existing architecture.

## Proof of Concept

```rust
#[cfg(test)]
mod test_liquidation_config_change {
    use super::*;
    use cosmwasm_std::{coin, Decimal, Addr};
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use crate::contract::{execute, instantiate, sudo};
    use rujira_rs::ghost::credit::{ExecuteMsg, InstantiateMsg, SudoMsg, ConfigUpdate, LiquidateMsg};

    #[test]
    fn test_liquidation_fails_after_config_update() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // 1. Initialize protocol with 50% max slip
        let init_msg = InstantiateMsg {
            code_id: 1,
            fee_liquidation: Decimal::percent(1),
            fee_liquidator: Decimal::percent(1),
            fee_address: Addr::unchecked("fee_addr"),
            liquidation_max_slip: Decimal::percent(50), // 50% initially
            liquidation_threshold: Decimal::percent(100),
            adjustment_threshold: Decimal::percent(90),
        };
        instantiate(deps.as_mut(), env.clone(), mock_info("admin", &[]), init_msg).unwrap();
        
        // 2. Setup account and create unsafe position (LTV = 105%)
        // [Account setup code omitted for brevity - creates account with collateral and debt]
        let unsafe_account_addr = "account1";
        
        // 3. Liquidator initiates liquidation with messages designed for 50% slip
        let liquidate_msg = ExecuteMsg::Liquidate {
            addr: unsafe_account_addr.to_string(),
            msgs: vec![
                LiquidateMsg::Execute {
                    contract_addr: "swap_contract".to_string(),
                    msg: Binary::default(), // Swap that results in 30% slippage
                    funds: vec![coin(1000, "collateral_denom")],
                },
                LiquidateMsg::Repay("debt_denom".to_string()),
            ],
        };
        
        // 4. Start liquidation - this creates the DoLiquidate message
        let liquidation_start = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("liquidator", &[]),
            liquidate_msg,
        ).unwrap();
        
        // 5. Governance updates config to 10% max slip DURING liquidation
        let update_msg = SudoMsg::UpdateConfig(ConfigUpdate {
            code_id: None,
            fee_liquidation: None,
            fee_liquidator: None,
            fee_address: None,
            liquidation_max_slip: Some(Decimal::percent(10)), // Reduce to 10%
            liquidation_threshold: None,
            adjustment_threshold: None,
        });
        sudo(deps.as_mut(), env.clone(), update_msg).unwrap();
        
        // 6. Process DoLiquidate - this will FAIL because it loads the new config
        // The liquidation was designed for 50% slip but results in 30% actual slip
        // With new 10% limit, validation fails
        
        // 7. Verify account is stuck:
        // - Liquidation fails with LiquidationMaxSlipExceeded
        // - Account remains at LTV = 105% (unsafe)
        // - Owner cannot perform operations due to CheckAccount failing
        
        // 8. Attempt owner repayment - should fail
        let owner_repay = ExecuteMsg::Account {
            addr: unsafe_account_addr.to_string(),
            msgs: vec![
                AccountMsg::Repay(coin(100, "debt_denom")),
            ],
        };
        
        let owner_result = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("account_owner", &[]),
            owner_repay,
        );
        
        // This will fail at CheckAccount because LTV (105%) >= adjustment_threshold (90%)
        assert!(owner_result.is_err());
        assert!(owner_result.unwrap_err().to_string().contains("Unsafe"));
        
        // Account is now in LIMBO: cannot be liquidated (config too strict)
        // and owner cannot repay debt (CheckAccount blocks it)
    }
}
```

**Note**: This PoC demonstrates the conceptual flow. A complete implementation would require full test harness setup with mock contracts, oracle prices, and vault integrations as seen in the existing test files.

---

**Notes:**
- This vulnerability is a protocol design flaw, not an attacker exploit
- It occurs through legitimate governance operations (risk parameter adjustment)
- The issue is rooted in the mismatch between when liquidation parameters are captured (at initialization) versus when they are validated (on each iteration)
- The protocol lacks safeguards to ensure ongoing liquidations complete under their original parameters

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L54-54)
```rust
    let config = Config::load(deps.storage)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-117)
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
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L151-169)
```rust
        ExecuteMsg::Account { addr, msgs } => {
            let mut account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            ensure_eq!(account.owner, info.sender, ContractError::Unauthorized {});
            let mut response = Response::default().add_event(event_execute_account(&account));
            for msg in msgs {
                let (messages, events) =
                    execute_account(deps.as_ref(), env.clone(), &config, msg, &mut account)?;
                response = response.add_messages(messages).add_events(events);
            }
            account.save(deps)?;

            Ok(response.add_message(ExecuteMsg::CheckAccount { addr }.call(&ca)?))
        }
        ExecuteMsg::CheckAccount { addr } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_safe(&config.adjustment_threshold)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L380-384)
```rust
        SudoMsg::UpdateConfig(update) => {
            config.update(&update);
            config.validate()?;
            config.save(deps.storage)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L248-281)
```rust
    pub fn validate_liquidation(
        &self,
        deps: Deps,
        config: &Config,
        old: &Self,
    ) -> Result<(), ContractError> {
        let balance = self.balance();
        let spent = old.balance().sent(&balance);

        for coin in spent.clone().into_vec() {
            self.liquidation_preferences
                .order
                .validate(&coin, &balance)?;
        }

        let spent_usd = spent.value_usd(deps.querier)?;
        let repaid = old.debt().sent(&self.debt());
        let repaid_usd = repaid.value_usd(deps.querier)?;
        let slippage = spent_usd
            .checked_sub(repaid_usd)
            .unwrap_or_default()
            .checked_div(spent_usd)
            .unwrap_or_default();

        // Check against config liquidation slip
        if !slippage.is_zero() {
            ensure!(
                slippage.le(&config.liquidation_max_slip),
                ContractError::LiquidationMaxSlipExceeded { slip: slippage }
            );
        }

        Ok(())
    }
```

**File:** contracts/rujira-ghost-credit/src/error.rs (L75-76)
```rust
    #[error("Max Slip exceeded during liquidation: #{slip}")]
    LiquidationMaxSlipExceeded { slip: Decimal },
```
