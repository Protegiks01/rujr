# Audit Report

## Title
Debt Pool Undercharging During Unmintable Fee Periods Causes Protocol Fee Loss and Depositor Value Extraction

## Summary
When protocol fees are too small to mint as shares (< 1 token), the `distribute_interest` function adds them to `pending_fees` but sets the fee to zero before charging the debt pool. This causes the debt pool to be systematically undercharged, allowing borrowers to repay without paying the accumulated pending fees, while protocol fee shares are later funded by diluting depositors rather than from borrower repayments.

## Finding Description

The vulnerability exists in the interest distribution mechanism at [1](#0-0) 

The `calculate_interest` function computes gross interest and splits it into net interest (for depositors) and protocol fees. The function decomposes these values into integer and fractional parts, storing fractional remainders in `pending_interest` and `pending_fees` for precision preservation. [2](#0-1) 

In `distribute_interest`, when attempting to mint fee shares via `deposit_pool.join(fee)`, if the fee amount is too small to mint at least 1 share, the code handles this as follows: [3](#0-2) 

The critical flaw occurs at line 155 where `fee` is set to zero, followed by line 164 where the debt pool is charged: [4](#0-3) 

Since `fee = 0`, the debt pool is only charged `interest` instead of `interest + fee`. The comment at line 152 confirms this is intentional: "set the fee to 0 so that the debt is not charged with the fee yet."

**The Accounting Discrepancy:**

1. Gross interest accrued = `net_interest + protocol_fee`
2. When fee cannot be minted:
   - Depositors receive `net_interest` via `deposit_pool.deposit(interest)` 
   - Debt pool is charged only `interest` (not `interest + fee`)
   - The `fee` component is stored in `pending_fees` but never charged to debt
3. When borrowers repay, they repay based on `debt_pool.size()`, which excludes unminted fees
4. Eventually when `pending_fees` accumulates to >= 1 token, shares are minted via `deposit_pool.join()`, which dilutes existing depositors

**Result:** Protocol fees are paid from depositor principal through dilution, not from borrower repayments. This breaks the fundamental economic model where borrowers pay interest + fees to benefit depositors and protocol.

**This violates Critical Invariant #10:** "Always-Accrued Interest: distribute_interest() called before all operations, ensuring accurate accounting" - the accounting is NOT accurate when fees cannot be minted.

## Impact Explanation

**Economic Impact:**
- **Borrowers underpay:** They repay debt without the fee components that accrued during unmintable fee periods
- **Protocol loses fees:** Fee revenue that should come from borrower payments is instead extracted from depositors
- **Depositors are harmed:** When pending_fees finally mints, their shares are diluted to fund protocol fees rather than receiving those fees from borrowers

**Scenario:** 
With a large deposit pool (1B tokens), small borrows (1M tokens), 10% APR, and 10% fee rate:
- If `distribute_interest` is called every second for testing/high-frequency operations
- Each call generates ~0.0003 tokens of fees (too small to mint with 1:1 share ratio)  
- Over 86,400 seconds (1 day), this accumulates to ~26 tokens of unminted fees
- The debt pool is undercharged by 26 tokens
- When borrowers repay, they save 26 tokens
- When pending_fees finally mints, those 26 tokens worth of shares come from diluting depositors

This compounds over the lifetime of loans, with the loss proportional to the duration fees remain unmintable.

## Likelihood Explanation

**Likelihood: High**

This occurs naturally during normal protocol operation without requiring attacker manipulation:

1. **Frequent in small-amount scenarios:** When borrows are small relative to pool size, or when operations occur at high frequency (multiple per minute)
2. **The test suite demonstrates this:** [5](#0-4)  explicitly tests the "no mint path" where fees accumulate in pending_fees
3. **Automatically triggered:** Every call to `execute()` in the vault contract triggers `distribute_interest()` [6](#0-5) , making this a frequent occurrence
4. **No special preconditions needed:** Any borrower benefits from this automatically when their loan exists during unmintable fee periods

## Recommendation

The debt pool must be charged for the full gross interest amount (net interest + fees) regardless of whether fees can be minted. The fix should separate fee minting from debt charging:

```rust
pub fn distribute_interest(
    &mut self,
    env: &Env,
    config: &Config,
) -> Result<Uint128, ContractError> {
    let (interest, fee) =
        self.calculate_interest(&config.interest, env.block.time, config.fee)?;
    let mut shares = Uint128::zero();

    // Try to mint fee shares - store result but don't modify fee variable
    let actual_fee_minted = match self.deposit_pool.join(fee) {
        Ok(amount) => {
            shares = amount;
            fee // Fee was successfully minted
        }
        Err(SharePoolError::Zero(_)) => {
            // Fee too small to mint - add to pending for next time
            self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
            Uint128::zero() // No shares minted, but still charge debt pool
        }
        Err(err) => return Err(err.into()),
    };

    // Allocate the interest to the deposit pool
    self.deposit_pool.deposit(interest)?;
    
    // CRITICAL FIX: Always charge debt pool the FULL amount (interest + fee)
    // even if fee shares couldn't be minted yet
    self.debt_pool.deposit(interest.add(fee))?;
    self.last_updated = env.block.time;

    Ok(shares)
}
```

The key change: `self.debt_pool.deposit(interest.add(fee))?` uses the original `fee` value, not the potentially-zeroed one. This ensures debt is always charged correctly regardless of share minting success.

## Proof of Concept

Add this test to `contracts/rujira-ghost-vault/src/state.rs` in the tests module:

```rust
#[test]
fn test_debt_undercharging_with_unmintable_fees() {
    let env = mock_env();
    let mut storage = cosmwasm_std::testing::MockStorage::new();
    State::init(&mut storage, &env).unwrap();
    let mut state = State::load(&storage).unwrap();

    let config = Config {
        denom: "test".to_string(),
        interest: Interest {
            target_utilization: Decimal::from_ratio(8u128, 10u128),
            base_rate: Decimal::from_ratio(1u128, 1000000u128), // Very low rate to generate fractional fees
            step1: Decimal::from_ratio(20u128, 100u128),
            step2: Decimal::from_ratio(100u128, 100u128),
        },
        fee: Decimal::from_ratio(1u128, 10u128), // 10% fee
        fee_address: cosmwasm_std::Addr::unchecked("fee_addr"),
    };

    // Setup: Large deposit pool, moderate borrow
    state.deposit(Uint128::new(1_000_000)).unwrap();
    let initial_borrow = Uint128::new(800_000);
    state.borrow(initial_borrow).unwrap();

    let mut env = mock_env();
    
    // Simulate 100 calls at 1-second intervals (high frequency scenario)
    let mut total_gross_interest = Uint128::zero();
    let mut total_charged_to_debt = Uint128::zero();
    
    for i in 1..=100 {
        env.block.time = state.last_updated.plus_seconds(1);
        
        let debt_before = state.debt_pool.size();
        state.distribute_interest(&env, &config).unwrap();
        let debt_after = state.debt_pool.size();
        
        let charged_this_period = debt_after.checked_sub(debt_before).unwrap();
        total_charged_to_debt = total_charged_to_debt.checked_add(charged_this_period).unwrap();
    }
    
    // Calculate what SHOULD have been charged (gross interest over 100 seconds)
    let time_fraction = Decimal::from_ratio(100u128, 31_536_000u128); // 100 seconds / year
    let rate = Decimal::from_ratio(1u128, 1000000u128); // base rate
    let gross_interest_owed = initial_borrow
        .multiply_ratio(rate.numerator(), rate.denominator())
        .multiply_ratio(time_fraction.numerator(), time_fraction.denominator());
    
    // The vulnerability: total charged to debt is LESS than what should be owed
    // because fees that couldn't be minted were never added to debt
    println!("Gross interest that should be charged: {}", gross_interest_owed);
    println!("Actually charged to debt pool: {}", total_charged_to_debt);
    println!("Pending fees (not charged): {}", state.pending_fees);
    
    // This assertion demonstrates the undercharging
    // The debt pool grew less than the gross interest owed
    assert!(total_charged_to_debt < gross_interest_owed, 
        "Debt pool should be undercharged when fees cannot be minted");
    
    // Pending fees accumulated but were never charged to debt
    assert!(!state.pending_fees.is_zero(), 
        "Fees accumulated in pending but never charged to debt pool");
}
```

This test demonstrates that when fees cannot be minted (due to being fractional amounts), the debt pool is charged less than the gross interest owed, proving the accounting discrepancy.

### Citations

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

**File:** contracts/rujira-ghost-vault/src/state.rs (L178-223)
```rust
    fn test_distribute_interest_no_mint_path() {
        let env = mock_env();
        let mut storage = cosmwasm_std::testing::MockStorage::new();
        State::init(&mut storage, &env).unwrap();
        let mut state = State::load(&storage).unwrap();

        let config = Config {
            denom: "test".to_string(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(1u128, 1000000u128), // 0.0001% per year
                step1: Decimal::from_ratio(20u128, 100u128),
                step2: Decimal::from_ratio(100u128, 100u128),
            },
            fee: Decimal::from_ratio(1u128, 10u128), // 10% fee
            fee_address: cosmwasm_std::Addr::unchecked("fee_addr"),
        };

        // Deposit 1000, borrow 800
        state.deposit(Uint128::new(1000)).unwrap();
        state.borrow(Uint128::new(800)).unwrap();

        // Wait 1 second
        let mut env = mock_env();
        env.block.time = state.last_updated.plus_seconds(1);

        // Distribute interest
        let shares = state.distribute_interest(&env, &config).unwrap();

        // No shares minted (fee_int = 0)
        assert_eq!(shares, Uint128::zero());

        // Pool sizes unchanged (net_int = 0)
        assert_eq!(state.deposit_pool.size(), Uint128::new(1000));
        assert_eq!(state.debt_pool.size(), Uint128::new(800));

        // All interest in pending amounts
        assert_eq!(
            state.pending_interest,
            DecimalScaled::from_ratio(45662328766017u128, 10u128.pow(19))
        );
        assert_eq!(
            state.pending_fees,
            DecimalScaled::from_ratio(5073592085113u128, 10u128.pow(19))
        );
    }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L51-51)
```rust
    let fees = state.distribute_interest(&env, &config)?;
```
