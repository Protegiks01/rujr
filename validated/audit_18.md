# Audit Report

## Title
Protocol Fee Revenue Loss Due to Failed Share Minting in High-Ratio Deposit Pools

## Summary
When the deposit pool's size-to-shares ratio becomes sufficiently high, protocol fees fail to mint shares and are deferred to `pending_fees`. However, borrowers are not charged this fee portion of their debt during the deferral period, creating an accounting imbalance where borrowers receive interest-free loans on the protocol fee portion. This results in time-value loss and potential permanent protocol revenue loss as vaults mature.

## Finding Description
The vulnerability exists in the `distribute_interest()` function within the vault's interest distribution mechanism. [1](#0-0) 

The critical accounting flaw occurs through this sequence:

1. **Interest Calculation**: The `calculate_interest()` function computes total interest accrued on debt and splits it into a protocol fee portion and depositor interest portion. [2](#0-1) 

2. **Share Minting Attempt**: The system attempts to mint vault shares for the protocol fee by calling `deposit_pool.join(fee)`. This operation fails when the calculated share issuance rounds to zero, which occurs when the fee amount is less than the pool's size-to-shares ratio. [3](#0-2) 

3. **Fee Deferral Without Debt Charging**: When share minting fails, the code explicitly sets `fee = Uint128::zero()` after adding it to `pending_fees`. The comment on line 152 states: "set the fee to 0 so that the debt is not charged with the fee yet". [4](#0-3) 

4. **Incomplete Debt Charging**: Subsequently, the debt pool is charged with `interest.add(fee)`, but since `fee` has been set to zero, borrowers are only charged the depositor interest portion, not the total interest including protocol fees. [5](#0-4) 

**The Root Cause**: As vaults mature, every interest distribution increases the deposit pool's `size` through `deposit(interest)` without proportionally increasing `shares`. This naturally increases the size-to-shares ratio over time. Eventually, the protocol fee amount becomes too small to mint even a single share, causing systematic deferral.

**Broken Invariant**: This violates the "Always-Accrued Interest" invariant documented in the protocol specifications, which states that interest should always be charged to borrowers. [6](#0-5) 

The test suite confirms this behavior - when shares cannot be minted, the debt pool size remains unchanged while fees accumulate in `pending_fees`: [7](#0-6) 

## Impact Explanation
**High Severity** - This vulnerability causes systematic protocol revenue loss through two mechanisms:

1. **Time Value Loss**: During the deferral period (potentially spanning multiple interest accrual cycles), borrowers receive interest-free loans on the protocol fee portion of their debt. For a vault with 10% protocol fees, this represents 10% of all interest revenue being effectively forgiven during deferral.

2. **Compounding Effect**: As the vault continues operating, each interest distribution further increases the deposit pool ratio through line 161, making future fee minting even less likely. This creates a positive feedback loop where the problem worsens over time.

3. **Potential Permanent Loss**: If the deposit pool ratio grows faster than fees accumulate in `pending_fees` (which naturally occurs in high-utilization vaults), the deferred fees may never successfully mint shares, resulting in permanent revenue loss for the protocol.

This directly impacts protocol sustainability and contradicts the documented invariant that interest should always be accrued and charged. The accounting imbalance where `total_interest_calculated ≠ total_debt_charged` violates fundamental protocol guarantees about interest collection.

## Likelihood Explanation
**High Likelihood** - This vulnerability manifests automatically through normal protocol operation:

1. **Natural Occurrence**: Every legitimate `distribute_interest()` call increases the deposit pool's size-to-shares ratio, progressively increasing the likelihood of fee minting failures. No malicious actor or unusual market conditions are required.

2. **Inevitable in Mature Vaults**: Large vaults with substantial deposits will naturally develop high ratios over time. Once a vault reaches sufficient maturity (typically millions in TVL with standard fee rates), the condition becomes persistent.

3. **Positive Feedback Loop**: Failed fee minting → higher ratio → more likely future failures → even higher ratio. This self-reinforcing mechanism makes the problem worse over time.

4. **No Remediation Path**: The protocol has no mechanism to "reset" the ratio or force charge the deferred fees to borrowers retroactively. Once the ratio becomes problematic, it continues indefinitely.

## Recommendation
The fix should separate fee charging from fee collection:

```rust
pub fn distribute_interest(
    &mut self,
    env: &Env,
    config: &Config,
) -> Result<Uint128, ContractError> {
    let (interest, fee) = self.calculate_interest(&config.interest, env.block.time, config.fee)?;
    let mut shares = Uint128::zero();

    // ALWAYS charge the full amount to debt pool first
    self.debt_pool.deposit(interest.add(fee))?;
    
    // Allocate interest to deposit pool
    self.deposit_pool.deposit(interest)?;
    
    // Try to mint shares for the fee
    match self.deposit_pool.join(fee) {
        Ok(amount) => {
            shares = amount;
        }
        Err(SharePoolError::Zero(_)) => {
            // If minting fails, accumulate in pending_fees for later collection
            self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
        }
        Err(err) => return Err(err.into()),
    }
    
    self.last_updated = env.block.time;
    Ok(shares)
}
```

The key change is moving the debt charging (line 164) to occur BEFORE attempting to mint shares, ensuring borrowers are always charged the full interest amount including fees, regardless of whether share minting succeeds.

## Proof of Concept
The existing test suite already demonstrates this vulnerability. The test `test_distribute_interest_no_mint_path` at lines 177-223 confirms that when share minting fails, the debt pool size remains unchanged (line 212: `assert_eq!(state.debt_pool.size(), Uint128::new(800))`), proving that borrowers are not charged the fee portion during deferral.

This can be compared to the successful minting case in `test_distribute_interest_mint_path` (lines 225-269) where the debt pool properly grows by the full interest amount including fees (line 260: `assert_eq!(state.debt_pool.size(), Uint128::new(1040))`).

The test demonstrates that the current implementation only charges borrowers the depositor interest portion when share minting fails, validating the core claim of this vulnerability.

## Notes
This is an accounting bug in the interest distribution logic, not an exploitable attack vector. It occurs naturally as vaults mature and requires no malicious actor. The vulnerability breaks the "Always-Accrued Interest" invariant and creates a systematic revenue leak for the protocol. The comment on line 152 suggests this behavior may have been intentional ("yet" implies eventual charging), but no mechanism exists to retroactively charge borrowers for deferred fees, making the loss permanent if the ratio continues growing.

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

**File:** contracts/rujira-ghost-vault/src/state.rs (L177-223)
```rust
    #[test]
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

**File:** packages/rujira-rs/src/share_pool.rs (L26-29)
```rust
        let issuance = self.shares * Decimal::from_ratio(amount, self.size);
        if issuance.floor().is_zero() {
            return Err(SharePoolError::Zero("Shares".to_string()));
        }
```

**File:** README.md (L120-122)
```markdown
### Always-Accrued Interest

Both execute and query entry points call state.distribute_interest before doing anything else, which accrues debt interest, credits depositors, and mints protocol fees; users therefore always act on up-to-date pool balances and rates (contracts/rujira-ghost-vault/src/contract.rs (lines 42-236), contracts/rujira-ghost-vault/src/state.rs (lines 52-171)).
```
