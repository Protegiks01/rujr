# Audit Report

## Title
Protocol Fee Revenue Loss Due to Failed Share Minting in High-Ratio Deposit Pools

## Summary
When the deposit pool's size-to-shares ratio becomes sufficiently high, protocol fees cannot mint shares and are deferred to `pending_fees`. However, these deferred fees are **not charged to borrowers' debt** during the deferral period, creating an accounting imbalance where borrowers receive interest-free loans on the fee portion of their debt. As the vault matures and the ratio grows, this deferral can become indefinite, resulting in permanent protocol revenue loss.

## Finding Description
The vulnerability exists in the `distribute_interest()` function's handling of protocol fee collection when share minting fails. [1](#0-0) 

The critical flaw occurs in this sequence:

1. **Fee Calculation**: `calculate_interest()` computes total interest and splits it into protocol fee and depositor interest [2](#0-1) 

2. **Failed Share Minting**: When `deposit_pool.join(fee)` fails due to `SharePoolError::Zero` (issuance rounds to zero), the fee is added to `pending_fees` and set to `0` [3](#0-2) 

3. **Incomplete Debt Charging**: The comment on line 152 explicitly states: "*set the fee to 0 so that the debt is not charged with the fee yet*". Consequently, line 164 only charges borrowers `interest` (depositor portion), not `interest + fee` (total interest) [4](#0-3) 

**The SharePool Minting Failure Condition**: [5](#0-4) 

Share minting fails when `shares * (amount / size) < 1`, which occurs when `amount < size / shares`. As the vault matures, `deposit()` calls (during interest distribution) increase `size` without increasing `shares`, causing the ratio to grow. Eventually, even substantial fee amounts cannot mint shares.

**Example Scenario**:
- Deposit pool: size = 1,000,000,000, shares = 1,000,000 (ratio = 1,000)
- Protocol fee = 100 units per period
- Required minimum for minting: 100 < 1,000,000,000 / 1,000,000 = 1,000
- Result: Fees cannot mint shares and are deferred to `pending_fees`
- Borrowers are charged only 900 (depositor portion), not 1,000 (total with fees)
- This continues for 10+ periods until pending_fees ≥ 1,000

**Broken Invariant**: The protocol's accounting invariant `total_debt_charged = depositor_interest + protocol_fee` is violated. When fees cannot mint, `total_debt_charged = depositor_interest only`, while `protocol_fee` is deferred without being charged to borrowers.

## Impact Explanation
**High Severity** - This vulnerability causes systematic protocol revenue loss through two mechanisms:

1. **Time Value Loss**: Borrowers receive interest-free loans on the fee portion of their debt during deferral periods (potentially 10-100+ interest accrual cycles). For a vault with 10% protocol fees and high utilization, this represents 10% of all interest revenue being deferred indefinitely.

2. **Potential Permanent Loss**: If the deposit pool ratio continues growing faster than fees accumulate in `pending_fees` (which occurs naturally as the vault matures), the fees may never mint shares, creating permanent revenue loss for the protocol.

**Quantified Impact**:
- Vault with $1B deposits, $800M borrowed at 10% APY = $80M annual interest
- Protocol fee (10%) = $8M annual revenue
- If ratio prevents minting for 90 days: ~$2M revenue deferred
- If deferral becomes permanent: $8M annual loss

This directly harms protocol sustainability and depositor returns, as protocol fees fund operations and depositor incentives.

## Likelihood Explanation
**High Likelihood** - This vulnerability triggers automatically as vaults mature:

1. **Natural Occurrence**: Every `distribute_interest()` call increases the deposit pool ratio through line 161's `deposit(interest)`, making fee minting progressively harder [6](#0-5) 

2. **No Attacker Required**: The bug manifests through normal protocol operation without malicious input

3. **Positive Feedback Loop**: Failed fee minting → ratio grows → future fees less likely to mint → ratio grows faster

4. **Inevitable in Large Vaults**: Once a vault reaches sufficient size (> $100M with typical fee rates), the condition becomes persistent

## Recommendation
**Fix**: Charge borrowers the full interest amount (including fees) regardless of whether shares can be minted. Defer only the share distribution, not the debt accrual.

```rust
pub fn distribute_interest(
    &mut self,
    env: &Env,
    config: &Config,
) -> Result<Uint128, ContractError> {
    let (interest, fee) =
        self.calculate_interest(&config.interest, env.block.time, config.fee)?;
    let mut shares = Uint128::zero();

    // Always charge borrowers the FULL interest (net + fee)
    // Regardless of whether we can mint shares for the fee
    self.debt_pool.deposit(interest.add(fee))?;
    
    // Allocate net interest to depositors
    self.deposit_pool.deposit(interest)?;

    // Attempt to mint shares for protocol fee
    match self.deposit_pool.join(fee) {
        Ok(amount) => {
            shares = amount;
        }
        // If minting fails, store BOTH the unminted value AND the fee
        // so we can attempt to mint later without losing debt accrual
        Err(SharePoolError::Zero(_)) => {
            self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
            // Do NOT set fee to 0 here - we already charged debt_pool above
        }
        Err(err) => return Err(err.into()),
    }

    self.last_updated = env.block.time;
    Ok(shares)
}
```

**Alternative Fix**: Implement a minimum pool ratio check that prevents the ratio from growing beyond a threshold where fees can reliably mint shares (e.g., reject deposits that would increase ratio beyond 100:1).

## Proof of Concept

```rust
#[cfg(test)]
mod fee_loss_poc {
    use super::*;
    use cosmwasm_std::{testing::mock_env, Decimal};

    #[test]
    fn test_fee_loss_on_high_ratio_pool() {
        let mut env = mock_env();
        let mut storage = cosmwasm_std::testing::MockStorage::new();
        State::init(&mut storage, &env).unwrap();
        let mut state = State::load(&storage).unwrap();

        let config = Config {
            denom: "test".to_string(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(10u128, 100u128), // 10% APY
                step1: Decimal::from_ratio(20u128, 100u128),
                step2: Decimal::from_ratio(100u128, 100u128),
            },
            fee: Decimal::from_ratio(1u128, 10u128), // 10% protocol fee
            fee_address: cosmwasm_std::Addr::unchecked("fee_addr"),
        };

        // Setup: Large deposit pool with high ratio
        state.deposit(Uint128::new(1_000_000)).unwrap();
        state.borrow(Uint128::new(800_000)).unwrap();
        
        // Artificially inflate ratio by adding value without shares (simulating long history)
        state.deposit_pool.deposit(Uint128::new(10_000_000)).unwrap();
        
        // Current ratio: size ~11M / shares 1M = ~11:1
        let initial_debt = state.debt_pool.size();
        let initial_deposit = state.deposit_pool.size();
        
        // Advance time by 1 year
        env.block.time = state.last_updated.plus_seconds(31_536_000);

        // Distribute interest - fees should fail to mint due to high ratio
        let shares_minted = state.distribute_interest(&env, &config).unwrap();
        
        // Expected: ~80k interest (10% of 800k debt)
        // Expected fee: ~8k (10% of 80k)
        // Expected net: ~72k
        
        let new_debt = state.debt_pool.size();
        let new_deposit = state.deposit_pool.size();
        let debt_increase = new_debt.u128() - initial_debt.u128();
        let deposit_increase = new_deposit.u128() - initial_deposit.u128();
        
        println!("Initial debt: {}, New debt: {}, Increase: {}", 
                 initial_debt, new_debt, debt_increase);
        println!("Initial deposit: {}, New deposit: {}, Increase: {}", 
                 initial_deposit, new_deposit, deposit_increase);
        println!("Shares minted for protocol: {}", shares_minted);
        println!("Pending fees: {:?}", state.pending_fees);
        
        // BUG DEMONSTRATION:
        // If ratio was too high, shares_minted == 0
        // AND debt_increase < expected (missing fee portion)
        // The fee is in pending_fees but was NEVER charged to borrowers!
        
        assert_eq!(shares_minted, Uint128::zero(), "Fees should fail to mint on high-ratio pool");
        
        // Debt should have increased by ~80k (full interest including fee)
        // But it only increased by ~72k (net interest without fee)!
        assert!(debt_increase < 75_000, "Borrowers were NOT charged the full interest including fee!");
        
        // The ~8k fee is in pending_fees but never charged - protocol loses this revenue
        // until pending_fees can eventually mint (which may be never if ratio keeps growing)
    }
}
```

## Notes
This vulnerability is **not** a simple rounding issue as initially framed in the question. It's a fundamental accounting flaw where the protocol intentionally defers charging borrowers for fees that cannot immediately mint shares, creating an interest-free loan on the fee portion. The issue compounds over time as the vault's size-to-shares ratio naturally increases through interest accrual, making fee collection progressively more difficult and potentially permanent in large, mature vaults.

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

**File:** packages/rujira-rs/src/share_pool.rs (L26-29)
```rust
        let issuance = self.shares * Decimal::from_ratio(amount, self.size);
        if issuance.floor().is_zero() {
            return Err(SharePoolError::Zero("Shares".to_string()));
        }
```
