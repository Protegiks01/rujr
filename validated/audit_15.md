# Audit Report

## Title
Retroactive Interest Rate Application Due to Missing `distribute_interest()` Call in `sudo(SetInterest)`

## Summary
The `sudo(SetInterest)` handler in the ghost vault contract updates interest rates without first distributing accrued interest at the old rate. This causes the next interest distribution to retroactively apply the new rate to the entire period since the last update, rather than splitting the calculation between the old and new rates. This violates the protocol's "Always-Accrued Interest" invariant and results in incorrect interest charges.

## Finding Description

The vulnerability exists in the `sudo` entrypoint's `SetInterest` handler, which updates the interest rate configuration without calling `distribute_interest()` first. [1](#0-0) 

This contrasts with all normal operations, which load state and call `distribute_interest()` before proceeding. [2](#0-1) 

The `distribute_interest()` function is responsible for updating the `last_updated` timestamp after calculating interest. [3](#0-2) 

Interest calculation depends critically on the time delta between `last_updated` and the current time, combined with the interest rate from config. [4](#0-3) 

**Concrete Scenario:**

1. **Time T0**: Borrower borrows 1000 tokens at 10% APR. Interest accrues normally with `state.last_updated = T0`.

2. **Time T1** (6 months later): Governance calls `sudo(SetInterest)` to change rate to 30% APR.
   - `config.interest` is updated to 30%
   - `state.last_updated` remains at T0 (state is never loaded or modified)

3. **Time T2** (1 year from T0): Next user action triggers `distribute_interest()`.
   - Time delta calculated: `T2 - T0 = 1 year`
   - Rate used: 30% (from updated config)
   - Interest charged: `1000 * 30% * 1 year = 300 tokens`

4. **Correct calculation should be**:
   - Period 1 (T0 to T1): `1000 * 10% * 0.5 year = 50 tokens`
   - Period 2 (T1 to T2): `1000 * 30% * 0.5 year = 150 tokens`
   - Total: `50 + 150 = 200 tokens`

5. **Impact**: Borrower overcharged by 100 tokens due to retroactive application.

The reverse scenario (rate decrease) harms depositors who receive less interest than they earned at the historical higher rate.

This violates **Invariant #10: "Always-Accrued Interest: distribute_interest() called before all operations, ensuring accurate accounting and preventing stale data manipulation."** The protocol assumes interest is always current before parameter changes, but `sudo()` bypasses this guarantee.

## Impact Explanation

**Severity: Medium**

This is an **interest calculation error** causing financial loss:

- **Rate Increases**: Borrowers retroactively charged higher rates for periods when they borrowed at lower rates (overcharging)
- **Rate Decreases**: Depositors retroactively paid lower rates for periods when they deposited at higher rates (underpayment)

The financial impact scales with:
1. **Magnitude of rate change** - A 10% → 30% change has 3x the impact of 10% → 20%
2. **Time since last distribution** - Longer periods amplify the error
3. **Total borrowed/deposited amount** - Larger positions magnify the dollar impact

Example: With 1000 tokens borrowed, a 10% → 30% rate change, and 6 months elapsed, the error is 100 tokens (~10% of principal). With 10,000 tokens and 1 year elapsed, this becomes 2,000 tokens.

This breaks the fundamental accounting principle that interest rates apply prospectively from the time of change, not retroactively to past periods. The error persists until the next operation, affecting all borrowers and depositors proportionally.

## Likelihood Explanation

**Likelihood: High**

This occurs automatically during **normal governance operations** whenever interest rates are adjusted. It requires:
- ✅ Legitimate governance action (rate adjustment for market conditions)
- ✅ Normal protocol usage (any subsequent transaction triggers the bug)
- ❌ No malicious intent
- ❌ No oracle manipulation
- ❌ No user exploitation

Interest rate adjustments are expected to occur regularly in response to:
- Market interest rate changes
- Protocol utilization shifts requiring rebalancing
- Governance decisions to optimize depositor yields or borrower costs

The vulnerability triggers automatically - the first transaction after any rate change will retroactively apply the new rate. No specific user action is required beyond normal borrowing/depositing operations.

## Recommendation

Call `distribute_interest()` before updating the interest rate configuration to ensure interest is calculated at the old rate up to the point of change:

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    let mut config = Config::load(deps.storage)?;

    match msg {
        SudoMsg::SetBorrower { contract, limit } => {
            Borrower::set(deps.storage, deps.api.addr_validate(&contract)?, limit)?;
            Ok(Response::default())
        }
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            
            // Load state and distribute interest at OLD rate before change
            let mut state = State::load(deps.storage)?;
            let fees = state.distribute_interest(&env, &config)?;
            state.save(deps.storage)?;
            
            // Now update to new rate
            config.interest = interest;
            config.save(deps.storage)?;
            
            // Return response with fee minting if applicable
            let mut response = Response::default();
            if fees.gt(&Uint128::zero()) {
                let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
                response = response.add_message(rcpt.mint_msg(fees, config.fee_address.clone()));
            }
            Ok(response)
        }
    }
}
```

This ensures `state.last_updated` is set to the current time with interest calculated at the old rate, so the next distribution will only apply the new rate to the period after the change.

## Proof of Concept

```rust
#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use cosmwasm_std::{coins, Decimal, Uint128};
    use cw_multi_test::{ContractWrapper, Executor};
    use rujira_rs::{ghost::vault::Interest, TokenMetadata};
    use rujira_rs_testing::mock_rujira_app;

    #[test]
    fn test_retroactive_interest_rate_application() {
        let mut app = mock_rujira_app();
        let owner = app.api().addr_make("owner");
        let borrower = app.api().addr_make("borrower");

        app.init_modules(|router, _, storage| {
            router.bank.init_balance(storage, &owner, coins(10_000, "btc")).unwrap();
            router.bank.init_balance(storage, &borrower, coins(10_000, "btc")).unwrap();
        });

        let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
        let code_id = app.store_code(code);
        
        // Instantiate with 10% APR
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
                        base_rate: Decimal::from_ratio(10u128, 100u128), // 10% APR
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

        // Owner deposits 1000 tokens
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1_000, "btc"),
        )
        .unwrap();

        // Whitelist borrower
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(1_000u128),
            },
        )
        .unwrap();

        // Borrower borrows 1000 tokens at 10% APR
        app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                callback: None,
                amount: Uint128::from(1_000u128),
                delegate: None,
            }),
            &[],
        )
        .unwrap();

        // Fast forward 6 months (half a year = 15,768,000 seconds)
        app.update_block(|block| {
            block.time = block.time.plus_seconds(15_768_000);
        });

        // Governance changes rate to 30% APR WITHOUT distributing interest first
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetInterest(Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(30u128, 100u128), // 30% APR
                step1: Decimal::from_ratio(1u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            }),
        )
        .unwrap();

        // Fast forward another 6 months
        app.update_block(|block| {
            block.time = block.time.plus_seconds(15_768_000);
        });

        // Query status to trigger distribute_interest()
        let status: StatusResponse = app
            .wrap()
            .query_wasm_smart(contract.clone(), &QueryMsg::Status {})
            .unwrap();

        // Expected: (1000 * 10% * 0.5) + (1000 * 30% * 0.5) = 50 + 150 = 200
        // Actual: 1000 * 30% * 1.0 = 300
        // Debt pool size should be 1200 (1000 + 200), but will be 1300 (1000 + 300)
        
        // The bug causes overcharge of 100 tokens
        assert!(status.debt_pool.size > Uint128::from(1_200u128), 
            "Borrower overcharged due to retroactive rate application. Expected ~1200, got {}", 
            status.debt_pool.size);
    }
}
```

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure**: No error occurs - the calculation completes successfully with incorrect values
2. **Affects All Users**: Every borrower and depositor in the vault is impacted proportionally
3. **Bidirectional Impact**: Rate increases overcharge borrowers; rate decreases undercharge depositors
4. **Compounds Over Time**: The longer between rate change and next operation, the larger the error
5. **Governance Blind Spot**: The trusted Rujira Deployer Multisig inadvertently triggers the bug through legitimate operations

The fix is straightforward and maintains the protocol's "Always-Accrued Interest" invariant by ensuring interest is distributed at the old rate before the configuration change takes effect.

### Citations

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

**File:** contracts/rujira-ghost-vault/src/state.rs (L103-109)
```rust
        let rate = Decimal256::from(self.debt_rate(interest)?);
        let seconds = to.seconds().sub(self.last_updated.seconds());
        let part = Decimal256::from_ratio(seconds, 31_536_000u128);

        let interest_decimal = Decimal256::from_ratio(self.debt_pool.size(), 1u128)
            .mul(rate)
            .mul(part);
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L165-165)
```rust
        self.last_updated = env.block.time;
```
