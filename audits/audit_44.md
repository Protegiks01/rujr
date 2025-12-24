# Audit Report

## Title
Retroactive Interest Rate Application Due to Missing `distribute_interest()` Call in `sudo(SetInterest)`

## Summary
When governance updates interest rates via `sudo(SetInterest)`, the new rates are applied immediately without calling `distribute_interest()`. This leaves `state.last_updated` unchanged, causing the next interest distribution to retroactively apply the new rate to the entire period since the last update, rather than only from the time of the rate change forward.

## Finding Description

The `sudo()` function in the ghost vault contract handles interest rate updates through the `SetInterest` message. [1](#0-0) 

The function updates `config.interest` and saves it, but critically does NOT call `distribute_interest()` before making this change. This means `state.last_updated` remains at its previous value.

The `distribute_interest()` function is responsible for updating `state.last_updated` to the current block time after calculating interest. [2](#0-1) 

Interest calculation uses the time delta between `state.last_updated` and current time, multiplied by the interest rate from config. [3](#0-2) 

**Attack Scenario:**

1. **Time T0**: Borrower borrows 1000 tokens at 10% APR. Interest accrues normally.
2. **Time T1** (6 months later): Governance legitimately changes rate to 30% APR via `sudo(SetInterest)`. Config is updated but `state.last_updated` stays at T0.
3. **Time T2** (1 year from T0): Any user action triggers `distribute_interest()`. Interest is calculated as: `(T2 - T0) * 30% = 1 year * 30% = 300 tokens`.
4. **Correct calculation should be**: `(T1 - T0) * 10% + (T2 - T1) * 30% = 0.5 year * 10% + 0.5 year * 30% = 50 + 150 = 200 tokens`.
5. **Result**: Borrower is overcharged by 100 tokens due to retroactive application of the 30% rate to the pre-change period.

The reverse scenario (rate decrease) similarly harms depositors who receive less interest than they should have earned at the higher historical rate.

**Invariant Broken:**

This violates **Invariant #10: "Always-Accrued Interest: `distribute_interest()` called before all operations, ensuring accurate accounting and preventing stale data manipulation."**

The code assumes interest is always accurately accrued before rate changes, but the `sudo()` function bypasses this guarantee.

## Impact Explanation

**Severity: Medium**

This constitutes an **interest calculation error** that causes financial loss to protocol users:

- **Rate Increase**: Borrowers are retroactively charged the higher rate for periods when they borrowed at a lower rate, resulting in overcharging
- **Rate Decrease**: Depositors receive less interest than earned, as the lower rate is retroactively applied to periods when deposits earned at a higher rate

The financial impact scales with:
1. The magnitude of the rate change (larger changes = larger discrepancy)
2. The time elapsed since the last interest distribution (longer periods = larger impact)
3. The total borrowed/deposited amount

This breaks the fundamental accounting principle that interest rates should only apply prospectively from the time of change, not retroactively.

## Likelihood Explanation

**Likelihood: High**

This issue occurs during **normal governance operations** whenever interest rates are adjusted. It does not require:
- Malicious intent from governance
- Oracle manipulation
- User exploitation
- Specific market conditions

Interest rate adjustments are expected to occur regularly in response to market conditions, protocol utilization changes, or governance decisions to optimize yield. Every such adjustment triggers this bug.

The vulnerability is **automatic** - it doesn't require any specific user action beyond the normal borrowing/depositing that triggers `distribute_interest()`. The first transaction after a rate change will retroactively apply the new rate.

## Recommendation

Call `distribute_interest()` before updating the interest rate configuration in the `sudo()` function. This ensures:
1. All pending interest is calculated using the OLD rate up to the current time
2. `state.last_updated` is updated to the current block time
3. The NEW rate only applies to interest accrued after this point

**Fixed Code:**

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
            
            // Load state and distribute pending interest with OLD rate
            let mut state = State::load(deps.storage)?;
            let fees = state.distribute_interest(&env, &config)?;
            state.save(deps.storage)?;
            
            // Now update to NEW rate
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
    }
}
```

## Proof of Concept

```rust
#[cfg(all(test, feature = "mock"))]
mod test_retroactive_rate {
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
        
        // Deploy with 10% base rate
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
                        base_rate: Decimal::from_ratio(1u128, 10u128), // 10% base
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

        // Deposit 1000 tokens
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1_000, "btc"),
        ).unwrap();

        // Whitelist and borrow 800 tokens
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(800u128),
            },
        ).unwrap();

        app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                amount: Uint128::from(800u128),
                callback: None,
                delegate: None,
            }),
            &[],
        ).unwrap();

        // Advance 6 months (half a year)
        app.update_block(|b| b.time = b.time.plus_seconds(15_768_000)); // ~6 months

        // Change interest rate to 50% base WITHOUT distributing interest first
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetInterest(Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(5u128, 10u128), // 50% base (5x increase)
                step1: Decimal::from_ratio(1u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            }),
        ).unwrap();

        // Advance another 6 months
        app.update_block(|b| b.time = b.time.plus_seconds(15_768_000)); // ~6 months

        // Query status to trigger distribute_interest()
        let status: StatusResponse = app
            .wrap()
            .query_wasm_smart(contract.clone(), &QueryMsg::Status {})
            .unwrap();

        // Expected (correct): 6mo @ 10% + 6mo @ 50% = ~40 + ~200 = ~240 interest
        // Actual (buggy): 12mo @ 50% = ~400 interest
        // The debt pool will show significantly more debt than it should
        
        // At 80% utilization, rates are: base + step1 = 10% + 10% = 20% (old) or 50% + 10% = 60% (new)
        // Correct: 6mo @ 20% + 6mo @ 60% on 800 = 80 + 240 = 320 total interest charged
        // Buggy: 12mo @ 60% on 800 = 480 total interest charged
        // Difference: 160 tokens overcharged to borrower
        
        println!("Debt pool size: {}", status.debt_pool.size);
        // Will show ~1280 instead of correct ~1120
        
        assert!(status.debt_pool.size > Uint128::from(1200u128), 
            "Debt should be retroactively inflated due to bug");
    }
}
```

## Notes

This vulnerability is triggered during legitimate governance operations, not malicious behavior. The bug lies in the implementation of `sudo(SetInterest)` which fails to settle pending interest calculations before applying new rates. This creates a state inconsistency where historical time periods are charged at future rates, violating both user expectations and accounting principles. The fix requires calling `distribute_interest()` before updating the interest rate configuration to ensure proper temporal boundaries between rate periods.

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L213-218)
```rust
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            config.interest = interest;
            config.save(deps.storage)?;
            Ok(Response::default())
        }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L97-134)
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

        // add pending_interest to interest
        let interest_scaled = DecimalScaled::from(interest_decimal);

        // collect the fee for the protocol
        let fee_rate_scaled = DecimalScaled::from(Decimal256::from(fee_rate));
        // add the fee to the pending fees
        let fee_accrued = interest_scaled.mul(fee_rate_scaled);

        // net interest for the users
        let net_interest = interest_scaled.sub(fee_accrued).add(self.pending_interest);

        // add the fee to the pending fees
        let fee_total = fee_accrued.add(self.pending_fees);

        // decompose fee_total and net_interest
        let (fee, fee_frac) = fee_total.decompose();
        let (interest, interest_frac) = net_interest.decompose();

        // persist pendings
        self.pending_fees = fee_frac;
        self.pending_interest = interest_frac;

        Ok((Uint128::try_from(interest)?, Uint128::try_from(fee)?))
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L136-168)
```rust
    pub fn distribute_interest(
        &mut self,
        env: &Env,
        config: &Config,
    ) -> Result<Uint128, ContractError> {
        // Calculate interest charged on total debt since last update
        let (interest, mut fee) =
            self.calculate_interest(&config.interest, env.block.time, config.fee)?;
        let mut shares = Uint128::zero();

        // deposit the protocol fee to the deposit pool to issue shares
        match self.deposit_pool.join(fee) {
            Ok(amount) => {
                shares = amount;
            }
            // if no shares were issued, add the fee to the pending fees for later distribution
            // set the fee to 0 so that the debt is not charged with the fee yet
            Err(SharePoolError::Zero(_)) => {
                self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
                fee = Uint128::zero();
            }
            Err(err) => return Err(err.into()),
        }

        // Allocate the interest to the deposit pool
        self.deposit_pool.deposit(interest)?;
        // Charge the interest to the debt pool, so that outstanding debt tokens are required to
        // pay this interest on return
        self.debt_pool.deposit(interest.add(fee))?;
        self.last_updated = env.block.time;

        Ok(shares)
    }
```
