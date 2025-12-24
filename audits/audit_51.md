# Audit Report

## Title
Interest Rate Changes Without Prior Distribution Cause Systematic Interest Miscalculation in Ghost Vaults

## Summary
When the admin updates interest rates via `SudoMsg::SetInterest`, the `sudo()` function fails to call `distribute_interest()` before applying the new rate configuration. This causes the accrued interest for the period since the last update to be calculated using the NEW rate instead of the OLD rate when the next transaction occurs, resulting in systematic over- or under-charging of interest to borrowers and incorrect returns to depositors.

## Finding Description
The vulnerability exists in the `sudo()` function's handling of `SudoMsg::SetInterest`. [1](#0-0) 

When this message is processed, it updates the interest configuration immediately without first distributing accrued interest under the old rate. In contrast, every `execute()` call correctly distributes interest before any operations. [2](#0-1) 

The `distribute_interest()` function calculates interest based on three factors: the current interest rate configuration, the time elapsed since `state.last_updated`, and the current debt pool size. [3](#0-2) 

**Attack Scenario:**
1. Time T0: Last transaction occurs, `state.last_updated = T0`, interest rate = 20% APR, debt pool = 1,000,000 tokens
2. Time T0 + 180 days: Admin calls `sudo(SetInterest)` to change rate to 5% APR
   - Config updated to 5% APR
   - State NOT updated, `last_updated` still = T0
3. Time T0 + 181 days: Next user transaction (deposit/withdraw/borrow/repay)
   - `execute()` calls `distribute_interest()`
   - Calculates interest for 181 days at NEW rate (5%) instead of:
     - 180 days at 20% APR
     - 1 day at 5% APR

**Calculation:**
- **Expected interest**: (1,000,000 × 0.20 × 180/365) + (1,000,000 × 0.05 × 1/365) = 98,630 + 137 = 98,767 tokens
- **Actual interest calculated**: 1,000,000 × 0.05 × 181/365 = 24,794 tokens
- **Loss to depositors**: 73,973 tokens (~75% of expected interest)

This breaks **Invariant #10**: "Always-Accrued Interest: distribute_interest() called before all operations, ensuring accurate accounting and preventing stale data manipulation."

The interest rate calculation uses the current configuration. [4](#0-3) 

## Impact Explanation
**HIGH SEVERITY** - This qualifies as a systemic interest calculation error with direct financial impact:

1. **Direct Economic Loss**: Depositors lose earned interest when rates decrease, borrowers are overcharged when rates increase
2. **Scales with Time**: The longer between rate changes and the next transaction, the greater the miscalculation
3. **Affects All Vault Users**: Every borrower and depositor in the affected vault is impacted
4. **Protocol Revenue Loss**: If rates decrease significantly, the protocol loses substantial fee revenue

Using realistic parameters:
- Vault with $10M TVL
- 80% utilization ($8M borrowed)
- Rate change from 15% to 3% APR
- 90 days until next transaction
- Lost interest: $8M × (0.15 - 0.03) × 90/365 = **$236,712**

## Likelihood Explanation
**HIGH LIKELIHOOD** - This will occur every time interest rates are updated:

1. **Frequent Operation**: Interest rate updates are a normal governance action responding to market conditions
2. **No Attacker Required**: This is a protocol logic bug, not an exploit requiring malicious actors
3. **Unavoidable**: Every rate change will trigger this miscalculation until the next transaction
4. **Low Activity Periods**: The impact is worse during low vault activity when time between transactions is longer

## Recommendation
The `sudo()` function must distribute accrued interest before updating the interest rate configuration:

```rust
SudoMsg::SetInterest(interest) => {
    interest.validate()?;
    
    // Load state and distribute interest under the old rate
    let mut state = State::load(deps.storage)?;
    let fees = state.distribute_interest(&env, &config)?;
    state.save(deps.storage)?;
    
    // Now update to the new rate
    config.interest = interest;
    config.save(deps.storage)?;
    
    // Mint fees if any
    let mut response = Response::default();
    if fees.gt(&Uint128::zero()) {
        let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
        response = response.add_message(rcpt.mint_msg(fees, config.fee_address.clone()));
    }
    
    Ok(response)
}
```

This ensures that:
1. Interest accrued under the old rate is properly calculated and distributed
2. The `last_updated` timestamp is synchronized with the rate change
3. Subsequent operations use the new rate only for new accrual periods

## Proof of Concept

```rust
#[cfg(test)]
mod interest_rate_change_exploit {
    use super::*;
    use cosmwasm_std::{coins, Decimal, Uint128};
    use cw_multi_test::{ContractWrapper, Executor};
    use rujira_rs::{ghost::vault::Interest, TokenMetadata};
    use rujira_rs_testing::mock_rujira_app;

    #[test]
    fn test_interest_miscalculation_on_rate_change() {
        let mut app = mock_rujira_app();
        let owner = app.api().addr_make("owner");
        let borrower = app.api().addr_make("borrower");

        // Initialize balances
        app.init_modules(|router, _, storage| {
            router.bank.init_balance(storage, &owner, coins(10_000_000, "btc")).unwrap();
            router.bank.init_balance(storage, &borrower, coins(10_000_000, "btc")).unwrap();
        });

        // Deploy vault with HIGH interest rate (20% APR)
        let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
        let code_id = app.store_code(code);
        let contract = app
            .instantiate_contract(
                code_id,
                owner.clone(),
                &InstantiateMsg {
                    denom: "btc".to_string(),
                    receipt: TokenMetadata {
                        description: "".to_string(),
                        display: "".to_string(),
                        name: "".to_string(),
                        symbol: "".to_string(),
                        uri: None,
                        uri_hash: None,
                    },
                    interest: Interest {
                        target_utilization: Decimal::from_ratio(8u128, 10u128),
                        base_rate: Decimal::from_ratio(20u128, 100u128), // 20% base rate
                        step1: Decimal::from_ratio(10u128, 100u128),
                        step2: Decimal::from_ratio(50u128, 100u128),
                    },
                    fee: Decimal::zero(),
                    fee_address: owner.to_string(),
                },
                &[],
                "vault",
                None,
            )
            .unwrap();

        // Deposit 1,000,000 tokens
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1_000_000u128, "btc"),
        )
        .unwrap();

        // Whitelist borrower
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(800_000u128),
            },
        )
        .unwrap();

        // Borrow 800,000 (80% utilization)
        app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                callback: None,
                amount: Uint128::from(800_000u128),
                delegate: None,
            }),
            &[],
        )
        .unwrap();

        // Advance 180 days (about 6 months)
        app.update_block(|x| x.time = x.time.plus_days(180));

        // Check interest at 20% rate (should be substantial)
        let status_before: StatusResponse = app
            .wrap()
            .query_wasm_smart(contract.clone(), &QueryMsg::Status {})
            .unwrap();
        
        // Expected: ~800,000 * 0.20 * 180/365 = 78,904 interest
        // Actual debt should be around 878,904
        let expected_debt_high_rate = Uint128::from(878_904u128);
        assert!(
            status_before.debt_pool.size >= Uint128::from(878_000u128),
            "Expected significant interest at 20% rate"
        );

        // Admin changes rate to LOW (5% APR) WITHOUT distributing interest first
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetInterest(Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(5u128, 100u128), // 5% base rate
                step1: Decimal::from_ratio(10u128, 100u128),
                step2: Decimal::from_ratio(50u128, 100u128),
            }),
        )
        .unwrap();

        // Advance 1 more day
        app.update_block(|x| x.time = x.time.plus_days(1));

        // Trigger interest distribution with any transaction
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1000u128, "btc"),
        )
        .unwrap();

        // Check final debt
        let status_after: StatusResponse = app
            .wrap()
            .query_wasm_smart(contract.clone(), &QueryMsg::Status {})
            .unwrap();

        // Interest calculated for 181 days at 5% instead of (180 days at 20% + 1 day at 5%)
        // Actual: 800,000 * 0.05 * 181/365 = 19,836
        // Expected: 78,904 (from 180 days at 20%) + 109 (1 day at 5%) = 79,013
        // Loss: ~59,177 tokens

        let actual_debt = status_after.debt_pool.size;
        let incorrect_interest = actual_debt.u128() - 800_000;
        
        println!("Initial debt: 800,000");
        println!("Expected interest (20% for 180d + 5% for 1d): ~79,013");
        println!("Actual interest calculated (5% for 181d): {}", incorrect_interest);
        println!("Loss to depositors: ~{}", 79_013 - incorrect_interest);

        // Verify the miscalculation: interest should be around 19,836 (way too low)
        assert!(
            actual_debt < Uint128::from(850_000u128),
            "Interest massively undercalculated due to rate change without distribution"
        );
        
        // The correct debt should have been close to 879,013
        // But actual is around 819,836 - a loss of ~59,177 tokens to depositors
    }
}
```

**Notes:**
- This vulnerability affects all vault operations where interest rates are updated
- The impact compounds with longer time periods between rate changes and subsequent transactions  
- Even legitimate governance actions (rate adjustments for market conditions) trigger this bug
- Query operations also call `distribute_interest()`, so they would reveal the miscalculation, but the damage is already done to the accounting
- The fix requires minimal code changes but is critical for accurate interest accounting

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L51-51)
```rust
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

**File:** contracts/rujira-ghost-vault/src/state.rs (L97-109)
```rust
    pub fn calculate_interest(
        &mut self,
        interest: &Interest,
        to: Timestamp,
        fee_rate: Decimal,
    ) -> Result<(Uint128, Uint128), ContractError> {
        let rate = Decimal256::from(self.debt_rate(interest)?);
        let seconds = to.seconds().sub(self.last_updated.seconds());
        let part = Decimal256::from_ratio(seconds, 31_536_000u128);

        let interest_decimal = Decimal256::from_ratio(self.debt_pool.size(), 1u128)
            .mul(rate)
            .mul(part);
```
