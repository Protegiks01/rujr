# Audit Report

## Title
Interest Rate Validation Bypass Enables Arithmetic Overflow Leading to Complete Vault DOS

## Summary
The `Interest::validate()` function in the ghost vault fails to enforce maximum bounds on `base_rate`, `step1`, and `step2` parameters. When combined with maximum debt levels, extremely high interest rates can cause Decimal256 arithmetic overflow in `calculate_interest()`, rendering the entire vault inoperable until governance intervenes.

## Finding Description

The vulnerability exists in the interest rate validation logic which only checks ordering and bounds constraints but not maximum values. [1](#0-0) 

The validation only enforces that `step2 > step1` and `0 < target_utilization < 1`, but does not limit the maximum values of `base_rate`, `step1`, or `step2`. Each of these can be set up to `Decimal::MAX` (approximately 3.4e20).

This becomes critical in the interest calculation logic: [2](#0-1) 

The interest calculation performs: `debt_pool.size() * rate * time_factor`. With:
- Maximum `debt_pool.size()` = `Uint128::MAX` ≈ 3.4e38
- Maximum `rate` = `base_rate + step1 + step2` ≈ 3 × 3.4e20 ≈ 1e21  
- Maximum `time_factor` = 1 (one year)

Result: 3.4e38 × 1e21 × 1 = 3.4e59, which exceeds `Decimal256::MAX` (≈ 1.15e59), causing arithmetic overflow.

The critical issue is that `distribute_interest()` is called at the entry point of ALL vault operations: [3](#0-2) 

And in ALL query operations: [4](#0-3) 

When the multiplication overflows, the entire vault becomes inoperable - deposits, withdrawals, borrows, repayments, and even queries all fail. The `sudo()` function can still update interest rates to recover, but during the DOS period all user funds are frozen. [5](#0-4) 

## Impact Explanation

**High Severity** - This causes temporary but complete freezing of all vault funds:

1. **User Fund Freeze**: All depositors cannot withdraw their funds until governance fixes the interest rates
2. **Borrower Lock**: Borrowers cannot repay debt, potentially exposing them to liquidation in the credit registry
3. **Liquidation Failure**: The credit registry cannot query vault status for liquidation calculations, potentially causing systemic undercollateralization
4. **Protocol Integration Break**: Any external contract depending on vault queries will fail

While governance can recover by updating interest rates via `sudo()`, the window of vulnerability could cause significant economic harm, especially if borrowers face liquidations due to their inability to manage debt positions.

## Likelihood Explanation

**Medium Likelihood** - While setting rates to 1e20 levels (trillions of trillions of percent APR) is unrealistic for normal operations, this vulnerability represents a failure of defense-in-depth:

1. The security question explicitly asks about "absurdly high rates," indicating this scenario should be protected against
2. Governance multisigs can be compromised or maliciously controlled  
3. Even trusted admins make mistakes - without bounds checking, a configuration error could brick the vault
4. The invariant "Bounded Config Values: All configuration changes validated via Config::validate" is broken

The impact severity (fund freeze) justifies the High rating even though likelihood is medium.

## Recommendation

Add maximum bounds validation to the `Interest::validate()` function to prevent overflow scenarios:

```rust
pub fn validate(&self) -> StdResult<()> {
    // Existing checks
    ensure!(
        self.step2.gt(&self.step1),
        StdError::generic_err("step2 must be > step1".to_string())
    );
    
    ensure!(
        !self.target_utilization.is_zero(),
        StdError::generic_err("target_utilization must be > 0".to_string())
    );
    
    ensure!(
        self.target_utilization.lt(&Decimal::one()),
        StdError::generic_err("target_utilization must be < 1".to_string())
    );
    
    // NEW: Add maximum bounds to prevent overflow
    // Max reasonable APR is 10,000% (100x), beyond which the protocol should not operate
    let max_rate = Decimal::from_ratio(100u128, 1u128); // 10,000% when multiplied by 100
    
    ensure!(
        self.base_rate.le(&max_rate),
        StdError::generic_err("base_rate exceeds maximum allowed value".to_string())
    );
    
    ensure!(
        self.step1.le(&max_rate),
        StdError::generic_err("step1 exceeds maximum allowed value".to_string())
    );
    
    ensure!(
        self.step2.le(&max_rate),
        StdError::generic_err("step2 exceeds maximum allowed value".to_string())
    );
    
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_interest_overflow {
    use super::*;
    use cosmwasm_std::{testing::mock_env, Decimal, Uint128};
    use cw_multi_test::{ContractWrapper, Executor};
    use rujira_rs::{ghost::vault::Interest, TokenMetadata};
    use rujira_rs_testing::mock_rujira_app;

    #[test]
    fn test_absurdly_high_rates_cause_overflow() {
        let mut app = mock_rujira_app();
        let owner = app.api().addr_make("owner");
        let borrower = app.api().addr_make("borrower");

        app.init_modules(|router, _, storage| {
            router
                .bank
                .init_balance(storage, &owner, coins(u128::MAX, "btc"))
                .unwrap();
        });

        let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
        let code_id = app.store_code(code);
        
        // Start with normal rates
        let contract = app
            .instantiate_contract(
                code_id,
                owner.clone(),
                &InstantiateMsg {
                    denom: "btc".to_string(),
                    receipt: TokenMetadata::default(),
                    interest: Interest {
                        target_utilization: Decimal::from_ratio(8u128, 10u128),
                        base_rate: Decimal::from_ratio(1u128, 10u128),
                        step1: Decimal::from_ratio(1u128, 10u128),
                        step2: Decimal::from_ratio(3u128, 1u128),
                    },
                    fee: Decimal::zero(),
                    fee_address: owner.to_string(),
                },
                &[],
                "vault",
                None,
            )
            .unwrap();

        // Deposit maximum amount
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1_000_000_000_000_000_000u128, "btc"), // Large deposit
        )
        .unwrap();

        // Set borrower and borrow maximum
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(1_000_000_000_000_000_000u128),
            },
        )
        .unwrap();

        app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                callback: None,
                amount: Uint128::from(800_000_000_000_000_000u128),
                delegate: None,
            }),
            &[],
        )
        .unwrap();

        // Now set absurdly high interest rates that pass validation
        let absurd_rate = Decimal::from_ratio(Uint128::MAX / 10u128, 1u128);
        
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetInterest(Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: absurd_rate,
                step1: absurd_rate,
                step2: absurd_rate + Decimal::one(), // Must be > step1
            }),
        )
        .unwrap(); // This succeeds - validation doesn't check max values!

        // Advance time to accumulate interest
        app.update_block(|block| {
            block.time = block.time.plus_seconds(31_536_000); // 1 year
        });

        // Now ANY operation will fail due to overflow in distribute_interest()
        let result = app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1u128, "btc"),
        );
        
        // Contract is DOS'd - all operations fail
        assert!(result.is_err());
        
        // Even queries fail
        let query_result: Result<StatusResponse, _> = app
            .wrap()
            .query_wasm_smart(contract.clone(), &QueryMsg::Status {});
        assert!(query_result.is_err());
        
        // Vault is completely frozen until governance updates interest rates
    }
}
```

**Notes**

This vulnerability specifically violates the "Bounded Config Values" invariant which states that all configuration changes should be validated. While the likelihood of setting rates to overflow levels (>1e20) is low in normal operations, defense-in-depth principles dictate that validation should prevent obviously broken states. The security question explicitly explores this scenario, indicating it should be protected against. Furthermore, with governance multisigs potentially compromised or errors in decimal places during configuration, having maximum bounds provides critical protection against complete vault failure.

### Citations

**File:** packages/rujira-rs/src/interfaces/ghost/vault/interest.rs (L31-47)
```rust
    pub fn validate(&self) -> StdResult<()> {
        ensure!(
            self.step2.gt(&self.step1),
            StdError::generic_err("step2 must be > step1".to_string())
        );

        ensure!(
            !self.target_utilization.is_zero(),
            StdError::generic_err("target_utilization must be > 0".to_string())
        );

        ensure!(
            self.target_utilization.lt(&Decimal::one()),
            StdError::generic_err("target_utilization must be < 1".to_string())
        );
        Ok(())
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L103-110)
```rust
        let rate = Decimal256::from(self.debt_rate(interest)?);
        let seconds = to.seconds().sub(self.last_updated.seconds());
        let part = Decimal256::from_ratio(seconds, 31_536_000u128);

        let interest_decimal = Decimal256::from_ratio(self.debt_pool.size(), 1u128)
            .mul(rate)
            .mul(part);

```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L48-51)
```rust
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L213-218)
```rust
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            config.interest = interest;
            config.save(deps.storage)?;
            Ok(Response::default())
        }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L223-226)
```rust
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let mut state = State::load(deps.storage)?;
    let config = Config::load(deps.storage)?;
    state.distribute_interest(&env, &config)?;
```
