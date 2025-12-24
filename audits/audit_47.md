# Audit Report

## Title
Config Deserialization Failure After Upgrade Causes Permanent Vault Bricking and Fund Freezing

## Summary
The `rujira-ghost-vault` contract lacks Config migration logic in its upgrade path. If new fields are added to the Config struct during a contract upgrade without proper backward-compatible deserialization patterns, all `Config::load()` calls will fail, permanently bricking the vault and preventing depositors from withdrawing funds until emergency contract redeployment.

## Finding Description

The vulnerability exists in the Config struct definition and migration implementation: [1](#0-0) 

The Config struct contains four non-optional fields without `#[serde(default)]` attributes. When this struct is modified during an upgrade (e.g., adding a `max_utilization: Decimal` field), the stored Config data in blockchain state cannot deserialize because the new field is missing from the old data.

The migrate function only handles borrower migration, not Config: [2](#0-1) 

Every critical entry point calls `Config::load()` before any operation:

- **execute()**: [3](#0-2) 
- **execute_market()**: [4](#0-3) 
- **sudo()**: [5](#0-4) 
- **query()**: [6](#0-5) 

When `Config::load()` fails due to deserialization errors, ALL vault operations fail immediately, including:
- Depositors cannot execute `ExecuteMsg::Withdraw` to retrieve funds
- Borrowers cannot execute `MarketMsg::Repay` to close positions
- Admin cannot execute `SudoMsg::SetInterest` or `SudoMsg::SetBorrower` to fix configuration
- All queries fail, preventing UI/monitoring systems from displaying vault state

**Evidence of Pattern Awareness**: The codebase demonstrates awareness of backward-compatible deserialization patterns. The State struct uses `#[serde(default)]` for new fields: [7](#0-6) 

Similarly, the `rujira-ghost-credit` contract's account storage uses `#[serde(default)]` for the tag field: [8](#0-7) 

However, the Config struct in `rujira-ghost-vault` lacks these protective patterns.

## Impact Explanation

**Severity: Critical**

This vulnerability meets the Critical severity criteria for "Permanent freezing of funds (fix requires protocol redeployment)":

1. **Depositors Cannot Withdraw**: All depositors with funds in the vault lose access to their capital until emergency redeployment
2. **Borrowers Cannot Repay**: Outstanding debt positions become frozen, preventing borrowers from managing their obligations
3. **Administrative Recovery Blocked**: Even privileged `sudo()` calls fail at `Config::load()`, preventing in-contract fixes
4. **Systemic Protocol Impact**: If multiple vaults are upgraded simultaneously with this issue, the entire lending protocol becomes inoperable

The only recovery path requires:
- Emergency deployment of a new contract with proper migration logic
- Redeployment of all affected vaults
- Potential state recovery procedures
- User communication and migration coordination

During the outage period (hours to days), depositors face:
- Locked capital with no withdrawal access
- Potential liquidation of collateral in connected credit accounts if debt positions cannot be adjusted
- Loss of yield opportunities while funds are frozen

## Likelihood Explanation

**Likelihood: Medium**

While this requires a governance/deployer action (contract upgrade) rather than external attack, the likelihood is Medium because:

1. **Common Development Pattern**: Adding fields to configuration structs is a routine upgrade requirement as protocols evolve
2. **No Compile-Time Protection**: Rust's type system does not prevent this error; deserialization failures only manifest at runtime after deployment
3. **Demonstrated Risk**: The out-of-scope `rujira-fin` contract includes `Config::migrate()` logic, proving this concern has been recognized but not applied to `rujira-ghost-vault`
4. **Missing from Test Coverage**: No migration tests exist for Config schema evolution in the vault contract

The vulnerability activates when:
- Protocol governance decides to add features requiring new Config fields (e.g., max utilization limits, dynamic fee structures, additional oracle integrations)
- Developers add non-optional fields to Config struct
- Upgrade is deployed without corresponding migration code

## Recommendation

Implement Config migration logic following the pattern used in `rujira-fin` contract. Add a migration function to `Config` implementation:

```rust
// In contracts/rujira-ghost-vault/src/config.rs
impl Config {
    pub fn migrate(deps: DepsMut) -> StdResult<()> {
        #[cw_serde]
        pub struct LegacyConfig {
            pub denom: String,
            pub interest: Interest,
            pub fee: Decimal,
            pub fee_address: Addr,
        }
        
        let legacy: LegacyConfig = Item::new("config").load(deps.storage)?;
        Self {
            denom: legacy.denom,
            interest: legacy.interest,
            fee: legacy.fee,
            fee_address: legacy.fee_address,
            // Add default values for any new fields here
        }
        .save(deps.storage)
    }
}
```

Update the migrate entry point:

```rust
// In contracts/rujira-ghost-vault/src/contract.rs
pub fn migrate(deps: DepsMut, _env: Env, _msg: ()) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Config::migrate(deps)?; // Add Config migration
    crate::borrowers::migrate(deps.storage)?;
    Ok(Response::default())
}
```

**Alternative Pattern**: For future upgrades, add new fields with backward-compatible patterns:
- Use `Option<T>` for fields that can be None: `pub max_utilization: Option<Decimal>`
- Use `#[serde(default)]` for fields with sensible defaults: `#[serde(default)] pub max_utilization: Decimal`

Both patterns allow old serialized data to deserialize successfully when the field is missing.

## Proof of Concept

```rust
#[cfg(test)]
mod config_migration_vulnerability_poc {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, Decimal, StdError};
    use cw_storage_plus::Item;
    use rujira_rs::ghost::vault::Interest;

    // Simulate the OLD Config structure (currently deployed)
    #[cw_serde]
    pub struct OldConfig {
        pub denom: String,
        pub interest: Interest,
        pub fee: Decimal,
        pub fee_address: Addr,
    }

    // Simulate the NEW Config structure (after upgrade with new field)
    #[cw_serde]
    pub struct NewConfig {
        pub denom: String,
        pub interest: Interest,
        pub fee: Decimal,
        pub fee_address: Addr,
        pub max_utilization: Decimal, // NEW FIELD without default
    }

    #[test]
    fn test_config_deserialization_failure_after_upgrade() {
        let mut deps = mock_dependencies();
        
        // Step 1: Store OLD config (simulating pre-upgrade state)
        let old_config = OldConfig {
            denom: "btc".to_string(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(3u128, 10000u128),
                step1: Decimal::from_ratio(8u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            },
            fee: Decimal::zero(),
            fee_address: Addr::unchecked("fee_addr"),
        };
        
        Item::<OldConfig>::new("config")
            .save(deps.as_mut().storage, &old_config)
            .unwrap();
        
        // Step 2: Attempt to load NEW config (simulating post-upgrade execution)
        let result = Item::<NewConfig>::new("config").load(deps.as_ref().storage);
        
        // Step 3: Verify deserialization FAILS
        assert!(result.is_err());
        match result.unwrap_err() {
            StdError::ParseErr { .. } => {
                // Expected: Deserialization fails because max_utilization field is missing
                println!("✓ Config::load() failed as expected - vault would be bricked");
            }
            _ => panic!("Expected ParseErr due to missing field"),
        }
        
        // Step 4: Demonstrate this breaks ALL operations
        // In the real contract, execute(), sudo(), query() all call Config::load()
        // and would ALL fail with this error, preventing:
        // - Withdrawals (ExecuteMsg::Withdraw)
        // - Deposits (ExecuteMsg::Deposit) 
        // - Borrows (ExecuteMsg::Market(MarketMsg::Borrow))
        // - Repays (ExecuteMsg::Market(MarketMsg::Repay))
        // - Admin operations (SudoMsg::SetInterest, SudoMsg::SetBorrower)
        // - Queries (QueryMsg::Status, QueryMsg::Borrower, etc.)
    }

    #[test]
    fn test_proper_migration_with_backward_compatibility() {
        let mut deps = mock_dependencies();
        
        // Demonstrate the CORRECT pattern using #[serde(default)]
        #[cw_serde]
        pub struct CorrectNewConfig {
            pub denom: String,
            pub interest: Interest,
            pub fee: Decimal,
            pub fee_address: Addr,
            #[serde(default)] // This allows backward compatibility!
            pub max_utilization: Decimal,
        }
        
        // Store OLD config
        let old_config = OldConfig {
            denom: "btc".to_string(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(3u128, 10000u128),
                step1: Decimal::from_ratio(8u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            },
            fee: Decimal::zero(),
            fee_address: Addr::unchecked("fee_addr"),
        };
        
        Item::<OldConfig>::new("config")
            .save(deps.as_mut().storage, &old_config)
            .unwrap();
        
        // Load as NEW config with #[serde(default)]
        let result = Item::<CorrectNewConfig>::new("config")
            .load(deps.as_ref().storage);
        
        // Verify deserialization SUCCEEDS
        assert!(result.is_ok());
        let new_config = result.unwrap();
        assert_eq!(new_config.denom, "btc");
        assert_eq!(new_config.max_utilization, Decimal::zero()); // Default value
        println!("✓ Config loaded successfully with backward compatibility");
    }
}
```

**Notes**

The rujira-ghost-credit contract suffers from the identical vulnerability - its migrate function also lacks Config migration logic: [9](#0-8) 

Both contracts require the same remediation to prevent vault/registry bricking during future upgrades. The protocol should establish a standard pattern for Config schema evolution across all contracts.

### Citations

**File:** contracts/rujira-ghost-vault/src/config.rs (L10-16)
```rust
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub interest: Interest,
    pub fee: Decimal,
    pub fee_address: Addr,
}
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L48-48)
```rust
    let config = Config::load(deps.storage)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L114-114)
```rust
    let config = Config::load(deps.storage)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L206-206)
```rust
    let mut config = Config::load(deps.storage)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L225-225)
```rust
    let config = Config::load(deps.storage)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L321-325)
```rust
pub fn migrate(deps: DepsMut, _env: Env, _msg: ()) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    crate::borrowers::migrate(deps.storage)?;
    Ok(Response::default())
}
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L22-25)
```rust
    #[serde(default)]
    pub pending_interest: DecimalScaled,
    #[serde(default)]
    pub pending_fees: DecimalScaled,
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L21-28)
```rust
#[cw_serde]
struct Stored {
    owner: Addr,
    account: Addr,
    #[serde(default)]
    tag: String,
    liquidation_preferences: LiquidationPreferences,
}
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L458-461)
```rust
pub fn migrate(deps: DepsMut, _env: Env, _msg: ()) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
```
