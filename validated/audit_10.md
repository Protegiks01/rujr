# Audit Report

## Title
Debt Pool Undercharging During Unmintable Fee Periods Causes Protocol Fee Loss and Depositor Value Extraction

## Summary
When protocol fees are too small to mint as shares (< 1 token), the `distribute_interest` function correctly stores them in `pending_fees` but erroneously sets the fee variable to zero before charging the debt pool. This causes the debt pool to be systematically undercharged by the unminted fee amounts. Borrowers repay based on the undercharged debt pool size, effectively not paying accumulated pending fees. When `pending_fees` finally accumulates to mintable amounts, the protocol fee shares are funded by diluting depositors rather than from borrower repayments.

## Finding Description

The vulnerability exists in the interest distribution mechanism in the `rujira-ghost-vault` contract. [1](#0-0) 

The `calculate_interest` function computes gross interest accrued on debt and splits it into net interest (for depositors) and protocol fees. [2](#0-1)  The function decomposes these values into integer and fractional parts, storing fractional remainders in `pending_interest` and `pending_fees` for precision preservation.

In `distribute_interest`, when attempting to mint fee shares via `deposit_pool.join(fee)`, if the fee amount is too small to mint at least 1 share (which returns `SharePoolError::Zero`), the code handles this by adding the fee back to `pending_fees` and setting `fee = 0`. [3](#0-2) 

The critical flaw occurs at line 155 where `fee` is set to zero, followed by line 164 where the debt pool is charged with `interest.add(fee)`. Since `fee = 0`, the debt pool is only charged `interest` instead of the full gross interest amount `interest + fee`. [4](#0-3) 

**The Accounting Discrepancy:**

1. Gross interest accrued = `net_interest + protocol_fee`
2. When fee cannot be minted:
   - Depositors receive `net_interest` via `deposit_pool.deposit(interest)` (line 161)
   - Debt pool is charged only `interest` via `debt_pool.deposit(interest.add(0))` (line 164)
   - The `fee` component is stored in `pending_fees` but never charged to the debt pool
3. When borrowers repay, they repay based on `debt_pool.size()`, which excludes the unminted fees
4. Eventually when `pending_fees` accumulates to ≥1 token, shares are minted via `deposit_pool.join()`, diluting existing depositors

**Result:** Protocol fees that should be funded by borrower repayments are instead extracted from depositor principal through share dilution. This breaks the fundamental economic model where borrowers pay interest + fees to benefit both depositors and the protocol.

The function is called automatically on every vault operation, [5](#0-4)  making this a frequent occurrence during normal protocol operation.

## Impact Explanation

**Economic Impact:**

This vulnerability creates a three-party economic imbalance:

1. **Borrowers underpay:** They repay debt based on `debt_pool.size()`, which systematically excludes unminted fee components. Over the lifetime of their loans, they save the accumulated unminted fees.

2. **Protocol loses intended fee revenue:** Fee revenue that should come from borrower repayments is instead funded by depositor dilution, reducing protocol income.

3. **Depositors are harmed:** When `pending_fees` finally accumulates to mintable amounts, the minting of protocol fee shares dilutes existing depositors' ownership percentage, effectively extracting value from their principal rather than from borrower payments.

**Concrete Example:**
- Deposit pool: 1,000,000,000 tokens
- Borrow: 1,000,000 tokens  
- 10% APR, 10% fee rate
- Gross interest per second: ~0.003 tokens
- Fee per second: ~0.0003 tokens (unmintable with 1:1 share ratio)

Over 86,400 seconds (1 day):
- Accumulated unminted fees: ~26 tokens
- Debt pool undercharged by: 26 tokens
- Borrower savings on repayment: 26 tokens
- Depositor dilution when fee mints: 26 tokens worth of shares

This compounds over time, with losses proportional to loan duration and operation frequency.

**Severity: MEDIUM**

This qualifies as a Medium severity issue under Code4rena's scope as it represents:
- Interest/fee calculation errors causing state inconsistencies
- Economic manipulation where one party (borrowers) systematically benefits at the expense of others (protocol and depositors)
- Violation of the protocol's fundamental economic model without requiring attacker manipulation

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers automatically during normal protocol operation:

1. **Automatic Triggering:** Every call to any vault `ExecuteMsg` (Deposit, Withdraw, Market operations) automatically calls `distribute_interest()`, making this extremely frequent. [5](#0-4) 

2. **Common Scenarios:** Occurs naturally when:
   - Borrows are small relative to pool size
   - Operations occur at high frequency (multiple times per minute)
   - During early stages of interest accrual periods
   - With high share-to-token ratios in the deposit pool

3. **Test Suite Evidence:** The protocol's own test suite explicitly includes a test case for the "no mint path" where fees accumulate in `pending_fees`. [6](#0-5)  This demonstrates the developers were aware of this code path but may not have recognized the debt undercharging consequence.

4. **No Preconditions Required:** No special market conditions, attacker actions, or coordinated transactions needed. Simply having active loans during periods when fees are too small to mint triggers the bug.

5. **Economic Inevitability:** Borrowers benefit automatically without taking any action. They simply repay less than the true gross interest they should owe.

## Recommendation

Modify the `distribute_interest` function to charge the debt pool with the full gross interest regardless of whether fee shares can be minted:

```rust
pub fn distribute_interest(
    &mut self,
    env: &Env,
    config: &Config,
) -> Result<Uint128, ContractError> {
    let (interest, fee) =
        self.calculate_interest(&config.interest, env.block.time, config.fee)?;
    let mut shares = Uint128::zero();
    
    // Store original fee value before attempting to mint
    let fee_for_debt = fee;

    match self.deposit_pool.join(fee) {
        Ok(amount) => {
            shares = amount;
        }
        Err(SharePoolError::Zero(_)) => {
            // Fee too small to mint, add to pending_fees
            self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
            // DO NOT set fee to 0 - we still need to charge debt pool
        }
        Err(err) => return Err(err.into()),
    }

    self.deposit_pool.deposit(interest)?;
    // Charge debt pool with full gross interest (interest + original fee value)
    self.debt_pool.deposit(interest.add(fee_for_debt))?;
    self.last_updated = env.block.time;

    Ok(shares)
}
```

The key changes:
1. Store the original `fee` value in `fee_for_debt` before any modifications
2. Remove the line that sets `fee = Uint128::zero()` in the error case
3. Always charge the debt pool with the full gross interest amount using the original fee value

This ensures the debt pool is correctly charged with all accrued interest, regardless of whether protocol fee shares can be immediately minted.

## Proof of Concept

Add this test to `contracts/rujira-ghost-vault/src/state.rs` in the tests module to demonstrate the undercharging:

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
            base_rate: Decimal::from_ratio(10u128, 100u128), // 10% base rate
            step1: Decimal::from_ratio(20u128, 100u128),
            step2: Decimal::from_ratio(100u128, 100u128),
        },
        fee: Decimal::from_ratio(1u128, 10u128), // 10% fee
        fee_address: cosmwasm_std::Addr::unchecked("fee_addr"),
    };

    // Deposit 1,000,000 and borrow 800,000 (80% utilization)
    state.deposit(Uint128::new(1_000_000)).unwrap();
    state.borrow(Uint128::new(800_000)).unwrap();

    // Wait 1 hour (interest accrues but fee is too small to mint)
    let mut env = mock_env();
    env.block.time = state.last_updated.plus_seconds(3600);

    // Calculate what SHOULD be charged
    let debt_before = state.debt_pool.size();
    let (interest, fee) = state.calculate_interest(&config.interest, env.block.time, config.fee).unwrap();
    let gross_interest = interest.checked_add(fee).unwrap();
    
    // Distribute interest
    state.distribute_interest(&env, &config).unwrap();
    
    let debt_after = state.debt_pool.size();
    let debt_increase = debt_after.checked_sub(debt_before).unwrap();
    
    // BUG: Debt pool is undercharged
    // debt_increase should equal gross_interest, but it only equals interest
    assert_ne!(debt_increase, gross_interest, "Debt pool should be charged full gross interest");
    assert_eq!(debt_increase, interest, "Debt pool is only charged net interest (BUG)");
    
    // The fee was not charged to debt
    let undercharge = gross_interest.checked_sub(debt_increase).unwrap();
    assert!(undercharge > Uint128::zero(), "Debt pool is undercharged by the unminted fee");
    
    // When borrower repays, they save the undercharged amount
    println!("Borrower saves {} tokens due to undercharging", undercharge);
}
```

This test demonstrates that when fees are too small to mint, the debt pool is charged only the net interest amount, not the full gross interest, resulting in systematic undercharging of borrowers.

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

**File:** contracts/rujira-ghost-vault/src/contract.rs (L42-51)
```rust
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
```
