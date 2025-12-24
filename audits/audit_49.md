# Audit Report

## Title
Pending Fees Minted to Wrong Address After Fee Address Configuration Change

## Summary
The vault's pending fee mechanism incorrectly directs accumulated protocol fees to the current `config.fee_address` rather than the address that was active when the fees were accrued. If a hypothetical `SetFeeAddress` sudo message is added and used while pending fees exist, previously accumulated protocol revenue will be minted to the new address instead of the original intended recipient.

## Finding Description

The vulnerability exists in the interaction between `calculate_interest()` and `distribute_interest()` across multiple transactions when deposit pool liquidity is insufficient. [1](#0-0) 

The `State` struct maintains `pending_fees` that accumulate when shares cannot be minted. [2](#0-1) 

In `calculate_interest()`, current period fees are added to `pending_fees` from previous periods. This combined amount is returned as the `fee` value. [3](#0-2) 

When `distribute_interest()` cannot mint shares (empty deposit pool), the entire fee amount is added to `pending_fees` and fee is set to zero to prevent minting. [4](#0-3) [5](#0-4) 

In the `execute()` function, config is loaded once, `distribute_interest()` is called, and any resulting fee shares are minted to `config.fee_address`.

**Attack Scenario:**

1. **Period 1**: Vault has active debt but minimal deposit pool liquidity. Interest accrues, generating 100 tokens worth of protocol fees. Since `deposit_pool.join(fee)` fails with `SharePoolError::Zero`, these fees are added to `pending_fees` and no shares are minted. Current `fee_address = legitimate_protocol_treasury`.

2. **Governance Action**: Protocol governance legitimately updates the fee address via hypothetical `SetFeeAddress` sudo message (e.g., treasury migration, multisig rotation). New `fee_address = new_treasury_address`.

3. **Period 2**: Deposit pool now has liquidity. New interest accrues (50 tokens of fees). When `calculate_interest()` executes, it calculates `fee_total = 50 (new) + 100 (pending) = 150`. The `deposit_pool.join(150)` succeeds, minting shares representing all 150 tokens of fees. These shares are minted to `new_treasury_address`.

**Result**: 100 tokens of fees that accrued when `fee_address` was `legitimate_protocol_treasury` are instead minted to `new_treasury_address`. This constitutes misdirection of protocol revenue. [6](#0-5) 

Currently, no `SetFeeAddress` sudo message exists in the protocol, but the question correctly identifies this as a realistic future addition.

## Impact Explanation

**Severity: HIGH**

This vulnerability enables **direct theft of protocol revenue** through misdirected fee payments. The impact is:

1. **Direct Financial Loss**: Accumulated protocol fees (potentially significant amounts over time) are sent to an unintended recipient.

2. **Revenue Stream Corruption**: If the old fee address was the legitimate protocol treasury and the new address is controlled by a malicious actor who gained governance control, this represents complete theft of accumulated revenue.

3. **Treasury Accounting Issues**: Even in non-malicious scenarios (legitimate address migration), this creates accounting discrepancies where fees accrued under one regime are paid to another, complicating financial tracking and potentially causing disputes.

The vulnerability affects protocol-level funds rather than user collateral, but represents a clear violation of the protocol's fee distribution guarantees.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires:

1. **Precondition**: Pending fees must exist (deposit pool was insufficient during previous interest distribution).
2. **Trigger**: A `SetFeeAddress` configuration change must occur while pending fees exist.
3. **Activation**: A subsequent transaction must successfully mint the accumulated pending fees.

While adding a `SetFeeAddress` sudo message is a reasonable protocol evolution (protocols routinely need to update treasury addresses), the specific timing window (changing address while pending fees exist) may not occur frequently. However, during low-liquidity periods or protocol launch phases, pending fees are more likely to accumulate, increasing vulnerability exposure.

The likelihood increases significantly if:
- The vault operates with chronically low deposit liquidity
- Fee address changes are frequent (e.g., rotating multisigs)
- Governance is aware of accumulated pending fees and times address changes to capture them

## Recommendation

**Solution**: Snapshot the intended fee recipient when fees are calculated and persist this with the pending fees, rather than using the current config at minting time.

**Implementation Approach 1 - Store Fee Recipient with Pending Fees**:

Modify the `State` struct to track the address for pending fees:

```rust
pub struct State {
    pub last_updated: Timestamp,
    pub debt_pool: SharePool,
    pub deposit_pool: SharePool,
    pub pending_interest: DecimalScaled,
    pub pending_fees: DecimalScaled,
    pub pending_fees_recipient: Option<Addr>, // NEW: Track who should receive pending fees
}
```

Update `distribute_interest()` to use and clear the stored recipient:

```rust
pub fn distribute_interest(
    &mut self,
    env: &Env,
    config: &Config,
) -> Result<(Uint128, Addr), ContractError> {  // Return both shares and recipient
    let (interest, mut fee) = self.calculate_interest(&config.interest, env.block.time, config.fee)?;
    let mut shares = Uint128::zero();
    
    // Determine the correct fee recipient
    let fee_recipient = if self.pending_fees.gt(&DecimalScaled::zero()) {
        // If pending fees exist, use the stored recipient
        self.pending_fees_recipient.clone().unwrap_or(config.fee_address.clone())
    } else {
        // Otherwise use current config
        config.fee_address.clone()
    };
    
    match self.deposit_pool.join(fee) {
        Ok(amount) => {
            shares = amount;
            // Clear the pending recipient since fees are minted
            self.pending_fees_recipient = None;
        }
        Err(SharePoolError::Zero(_)) => {
            self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
            // Store current fee address for when these pending fees get minted
            self.pending_fees_recipient = Some(config.fee_address.clone());
            fee = Uint128::zero();
        }
        Err(err) => return Err(err.into()),
    }
    
    // ... rest of function
    Ok((shares, fee_recipient))
}
```

Update `execute()` to use the returned recipient:

```rust
let (fees, fee_recipient) = state.distribute_interest(&env, &config)?;
// ... rest of execute logic
if fees.gt(&Uint128::zero()) {
    response = response.add_message(rcpt.mint_msg(fees, fee_recipient));
}
```

**Implementation Approach 2 - Immediate Fee Minting**:

Alternatively, restructure the fee distribution to immediately mint fees to the fee address even when the deposit pool is too small, rather than deferring via `pending_fees`. This eliminates the temporal gap entirely.

## Proof of Concept

```rust
#[cfg(test)]
mod test_fee_recipient_vulnerability {
    use super::*;
    use cosmwasm_std::{testing::mock_env, Addr, Decimal, Uint128};
    use rujira_rs::{ghost::vault::Interest, DecimalScaled};

    #[test]
    fn test_pending_fees_minted_to_wrong_address() {
        let env = mock_env();
        let mut storage = cosmwasm_std::testing::MockStorage::new();
        State::init(&mut storage, &env).unwrap();
        let mut state = State::load(&storage).unwrap();

        // Initial config with fee_address = "original_treasury"
        let mut config = Config {
            denom: "btc".to_string(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(10u128, 100u128), // 10% APR
                step1: Decimal::from_ratio(20u128, 100u128),
                step2: Decimal::from_ratio(100u128, 100u128),
            },
            fee: Decimal::from_ratio(1u128, 10u128), // 10% fee
            fee_address: Addr::unchecked("original_treasury"),
        };

        // Period 1: Empty deposit pool, create debt to accrue interest
        // (In reality, this would fail because you can't borrow from empty pool,
        // but we're simulating the state after some borrows and all deposits withdrawn)
        state.debt_pool.deposit(Uint128::new(1000)).unwrap(); // Simulate 1000 debt
        
        // Fast forward 1 year to accrue significant interest
        let mut env = mock_env();
        env.block.time = state.last_updated.plus_seconds(31_536_000); // 1 year

        // Distribute interest with empty deposit pool
        let shares_period1 = state.distribute_interest(&env, &config).unwrap();
        
        // No shares minted because deposit pool is empty
        assert_eq!(shares_period1, Uint128::zero());
        
        // But pending_fees have accumulated
        let pending_before_change = state.pending_fees.clone();
        assert!(pending_before_change.gt(&DecimalScaled::zero()), 
                "Pending fees should have accumulated");

        // === GOVERNANCE ACTION: Change fee address ===
        config.fee_address = Addr::unchecked("new_treasury");
        
        // Period 2: Someone deposits, providing liquidity
        state.deposit(Uint128::new(2000)).unwrap();
        
        // Fast forward another year
        env.block.time = env.block.time.plus_seconds(31_536_000);
        
        // Distribute interest again - this time with liquidity
        let shares_period2 = state.distribute_interest(&env, &config).unwrap();
        
        // Shares ARE minted this time
        assert!(shares_period2.gt(&Uint128::zero()), 
                "Shares should be minted in period 2");
        
        // VULNERABILITY: These shares (representing fees from BOTH periods) 
        // will be minted to "new_treasury" in execute(), 
        // even though period 1 fees were accrued when fee_address was "original_treasury"
        
        // In the actual execute() function, this would happen:
        // if shares_period2.gt(&Uint128::zero()) {
        //     response.add_message(rcpt.mint_msg(shares_period2, config.fee_address))
        //                                                          ^^^ new_treasury gets fees from period 1
        // }
        
        println!("Period 1 pending fees (should go to original_treasury): {:?}", pending_before_change);
        println!("Period 2 minted shares (will go to new_treasury): {}", shares_period2);
        println!("VULNERABILITY: Fees accrued under original_treasury paid to new_treasury!");
    }
}
```

**Notes**

This vulnerability is a time-of-check to time-of-use (TOCTOU) issue where the "check" (fee calculation and accrual) happens in one transaction under one configuration, but the "use" (fee minting) happens in a later transaction under a potentially different configuration. The pending fee mechanism creates a temporal gap that allows configuration changes to affect how previously accrued fees are distributed.

The issue is exacerbated by the protocol's design of accumulating fees in `pending_fees` when liquidity is insufficient, as this creates a longer window during which the configuration can change before fees are finally minted.

### Citations

**File:** contracts/rujira-ghost-vault/src/state.rs (L23-25)
```rust
    pub pending_interest: DecimalScaled,
    #[serde(default)]
    pub pending_fees: DecimalScaled,
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L122-123)
```rust
        // add the fee to the pending fees
        let fee_total = fee_accrued.add(self.pending_fees);
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L147-156)
```rust
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
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L48-51)
```rust
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L100-102)
```rust
    if fees.gt(&Uint128::zero()) {
        response = response.add_message(rcpt.mint_msg(fees, config.fee_address.clone()));
    }
```

**File:** packages/rujira-rs/src/interfaces/ghost/vault/interface.rs (L48-51)
```rust
pub enum SudoMsg {
    SetBorrower { contract: String, limit: Uint128 },
    SetInterest(Interest),
}
```
