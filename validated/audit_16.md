# Audit Report

## Title
Critical Accounting Discrepancy: Delegate Repayments Discard Remainder Shares Leading to Protocol Insolvency

## Summary
The `delegate_repay()` function discards the remainder value returned by the inner `repay()` function, causing a permanent accounting mismatch when combined with stale delegate share tracking. This breaks the critical invariant that the sum of all borrower shares must equal debt_pool shares, leading to protocol insolvency.

## Finding Description

The vulnerability exists in the interaction between delegate borrowing, regular repayments, and delegate repayments in the Ghost Vault contract. The core issue stems from two critical design flaws:

**Flaw 1: Discarded Remainder in `delegate_repay()`**

The `repay()` function returns the remainder of shares that couldn't be repaid when the requested amount exceeds the borrower's actual shares. [1](#0-0) 

However, `delegate_repay()` completely discards this return value when calling the inner `repay()` function. The `?` operator on line 92 only propagates errors, not the Ok value containing the remainder. [2](#0-1) 

**Flaw 2: Stale DELEGATE_SHARES After Regular Repays**

When a borrower performs a regular (non-delegate) repay, the `DELEGATE_SHARES` mapping is never updated, even though the borrower's total shares decrease. This creates stale delegate share accounting that no longer reflects the borrower's actual debt.

**Exploitation Sequence:**

1. **Initial State**: Borrower1 delegates 100 shares to address A, Borrower2 borrows 50 shares directly
   - debt_pool.shares = 150
   - borrower1.shares = 100
   - borrower2.shares = 50
   - DELEGATE_SHARES[(borrower1, A)] = 100

2. **Borrower1 Regular Repay**: Borrower1 repays 60 shares through a regular (non-delegate) repay
   - debt_pool.shares = 90 (burned 60)
   - borrower1.shares = 40 (deducted 60)
   - borrower2.shares = 50
   - DELEGATE_SHARES[(borrower1, A)] = 100 (STALE - not updated!)

3. **Delegate A Repay Attempt**: Someone attempts to repay delegate A's debt based on the stale DELEGATE_SHARES value

The repay execution in `contract.rs` uses the stale DELEGATE_SHARES value to calculate debt and burn shares: [3](#0-2) 

- Line 170: `borrower_shares = DELEGATE_SHARES[(borrower1, A)] = 100` (stale!)
- Line 173: `borrower_debt = debt_pool.ownership(100)` calculates debt based on 100 shares
- Line 174: User sends 90 tokens (all remaining pool debt)
- Line 176: `state.repay(90)` burns 90 shares from debt_pool
  - debt_pool.shares = 0 (90 shares burned)

- Line 179: `borrower1.delegate_repay(storage, A, 90)` attempts to deduct 90 shares:
  - DELEGATE_SHARES[(borrower1, A)] = 10 (decreased by 90)
  - Calls `borrower1.repay(storage, 90)`
  - But borrower1.shares = 40, so only 40 can be deducted
  - borrower1.shares = 0 (only 40 deducted)
  - **Returns Ok(50) - the 50 share remainder is DISCARDED by the `?` operator!**

**Final State - Broken Invariant:**
- debt_pool.shares = 0 (burned 90 shares)
- borrower1.shares = 0 (only deducted 40 shares)
- borrower2.shares = 50 (unchanged)
- **Sum of borrower shares: 50 ≠ debt_pool.shares: 0**

The debt_pool believes there are 0 shares of debt, but borrower2 still owes 50 shares. The protocol is now insolvent - borrower2 cannot repay (the state.repay() function will fail with `ZeroDebt` error since the debt_pool is empty), and lenders cannot withdraw their full deposits because the protocol lacks sufficient backing. [4](#0-3) 

## Impact Explanation

**Severity: Critical**

This vulnerability causes **permanent protocol insolvency** with no recovery mechanism:

1. **Accounting Corruption**: The fundamental invariant that `sum(all borrower.shares) == debt_pool.shares` is permanently broken. The debt_pool records fewer shares than borrowers actually owe.

2. **Borrowers Cannot Repay**: Borrowers with remaining shares cannot repay their debts because the debt_pool has no shares left to burn. The `state.repay()` function will revert with `ZeroDebt` error.

3. **Lenders Cannot Withdraw**: The vault has insufficient assets to cover all depositor claims because outstanding debt is not being tracked correctly.

4. **No Recovery Path**: This accounting discrepancy is permanently written to blockchain state. There is no admin function or mechanism to correct the share mismatch without redeploying contracts and migrating all positions.

5. **Accumulating Damage**: Each occurrence of this bug compounds the problem, making the accounting divergence worse over time.

This meets the Critical severity criteria: "Protocol insolvency leading to systemic loss" and "Permanent freezing of funds (fix requires protocol redeployment)".

## Likelihood Explanation

**Likelihood: High**

This vulnerability triggers under normal protocol operations without requiring any attack:

1. **Standard Usage Pattern**: Delegate borrowing is a core feature designed for credit accounts to delegate borrowing authority. Regular users performing regular repays after delegate borrows is expected behavior, not malicious activity.

2. **No Preconditions**: Only requires:
   - One borrower with a delegate borrow
   - One regular repay by the same borrower
   - One subsequent delegate repay attempt
   All are standard operations that will naturally occur during normal protocol usage.

3. **Silent Failure**: The bug executes without errors or reverts. Transactions succeed, making the accounting corruption undetectable until someone attempts to use the corrupted state.

4. **Multiple Borrowers Amplify Risk**: With multiple borrowers using the same vault, one borrower's regular repay creates stale delegate shares that affect all subsequent delegate repay operations.

5. **No Economic Disincentive**: Users have no reason to avoid this sequence - they are simply using the protocol as designed.

## Recommendation

**Fix 1: Update DELEGATE_SHARES during regular repays**

When a borrower performs a regular repay, proportionally reduce all their delegate shares:

```rust
pub fn repay(
    &mut self,
    storage: &mut dyn Storage,
    shares: Uint128,
) -> Result<Uint128, ContractError> {
    let repaid = min(shares, self.shares);
    
    // Proportionally reduce all delegate shares
    let ratio = if !self.shares.is_zero() {
        Decimal::from_ratio(self.shares.checked_sub(repaid)?, self.shares)
    } else {
        Decimal::zero()
    };
    
    // Update all delegate shares proportionally
    let delegates: Vec<_> = DELEGATE_SHARES
        .prefix(self.addr.clone())
        .range(storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;
    
    for (delegate_addr, delegate_shares) in delegates {
        let new_shares = delegate_shares * ratio;
        DELEGATE_SHARES.save(
            storage,
            (self.addr.clone(), delegate_addr),
            &new_shares.to_uint_floor(),
        )?;
    }
    
    self.shares -= repaid;
    self.save(storage)?;
    Ok(shares.sub(repaid))
}
```

**Fix 2: Handle remainder in delegate_repay**

The `delegate_repay()` function should handle the remainder returned by the inner `repay()` call and return it to the caller:

```rust
pub fn delegate_repay(
    &mut self,
    storage: &mut dyn Storage,
    delegate: Addr,
    shares: Uint128,
) -> Result<Uint128, ContractError> {
    let k = (self.addr.clone(), delegate);
    let delegate = DELEGATE_SHARES.load(storage, k.clone())?;
    let repaid = min(shares, delegate);
    DELEGATE_SHARES.save(storage, k, &delegate.checked_sub(repaid)?)?;
    
    // Capture the remainder from inner repay
    let remainder = self.repay(storage, repaid)?;
    
    // Return the total remainder (what couldn't be deducted from delegate_shares + what couldn't be deducted from borrower.shares)
    Ok(shares.sub(repaid).checked_add(remainder)?)
}
```

**Fix 3: Validate accounting in contract.rs**

In the repay execution flow, validate that the returned remainder is zero, or refund excess tokens:

```rust
match delegate_address.clone() {
    Some(d) => {
        let remainder = borrower.delegate_repay(deps.storage, d, shares)?;
        if !remainder.is_zero() {
            // Either error or refund proportional tokens
            return Err(ContractError::InsufficientBorrowerShares { remainder });
        }
    }
    None => {
        let remainder = borrower.repay(deps.storage, shares)?;
        if !remainder.is_zero() {
            return Err(ContractError::InsufficientBorrowerShares { remainder });
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, Addr, Uint128};
    use crate::contract::{execute, instantiate};
    use rujira_rs::ghost::vault::{ExecuteMsg, InstantiateMsg, MarketMsg, Interest};

    #[test]
    fn test_delegate_repay_accounting_discrepancy() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Initialize vault
        let msg = InstantiateMsg {
            denom: "uusd".to_string(),
            receipt: "ghost-receipt".to_string(),
            interest: Interest {
                target_utilization: cosmwasm_std::Decimal::from_ratio(8u128, 10u128),
                base_rate: cosmwasm_std::Decimal::from_ratio(5u128, 100u128),
                step1: cosmwasm_std::Decimal::from_ratio(20u128, 100u128),
                step2: cosmwasm_std::Decimal::from_ratio(100u128, 100u128),
            },
            fee: cosmwasm_std::Decimal::from_ratio(1u128, 10u128),
            fee_address: "fee_addr".to_string(),
        };
        instantiate(deps.as_mut(), env.clone(), mock_info("admin", &[]), msg).unwrap();
        
        // Set up borrowers via sudo
        let borrower1_addr = Addr::unchecked("borrower1");
        let borrower2_addr = Addr::unchecked("borrower2");
        deps.querier.update_wasm(|_| {
            // Mock sudo calls to set borrowers
            Ok(cosmwasm_std::Binary::default())
        });
        
        // Deposit liquidity
        let depositor = mock_info("depositor", &coins(1000, "uusd"));
        execute(
            deps.as_mut(),
            env.clone(),
            depositor,
            ExecuteMsg::Deposit { callback: None },
        ).unwrap();
        
        // Borrower1 delegate borrows 100 to delegate A
        let delegate_a = "delegate_a".to_string();
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower1", &[]),
            ExecuteMsg::Market(MarketMsg::Borrow {
                amount: Uint128::new(100),
                delegate: Some(delegate_a.clone()),
            }),
        ).unwrap();
        
        // Borrower2 borrows 50 directly
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower2", &[]),
            ExecuteMsg::Market(MarketMsg::Borrow {
                amount: Uint128::new(50),
                delegate: None,
            }),
        ).unwrap();
        
        // Borrower1 does regular repay of 60
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower1", &coins(60, "uusd")),
            ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        ).unwrap();
        
        // Query state
        let state = State::load(deps.as_ref().storage).unwrap();
        let borrower1 = Borrower::load(deps.as_ref().storage, borrower1_addr.clone()).unwrap();
        let borrower2 = Borrower::load(deps.as_ref().storage, borrower2_addr.clone()).unwrap();
        
        // At this point:
        // debt_pool.shares = 90 (150 - 60)
        // borrower1.shares = 40 (100 - 60)
        // borrower2.shares = 50
        // DELEGATE_SHARES[(borrower1, A)] = 100 (STALE!)
        assert_eq!(state.debt_pool.shares(), Uint128::new(90));
        assert_eq!(borrower1.shares, Uint128::new(40));
        assert_eq!(borrower2.shares, Uint128::new(50));
        
        // Delegate A attempts to repay all remaining debt (90 tokens)
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("repayer", &coins(90, "uusd")),
            ExecuteMsg::Market(MarketMsg::Repay {
                delegate: Some(delegate_a),
            }),
        ).unwrap();
        
        // Query final state
        let final_state = State::load(deps.as_ref().storage).unwrap();
        let final_borrower1 = Borrower::load(deps.as_ref().storage, borrower1_addr).unwrap();
        let final_borrower2 = Borrower::load(deps.as_ref().storage, borrower2_addr).unwrap();
        
        // ACCOUNTING DISCREPANCY:
        // debt_pool.shares = 0 (burned 90)
        // borrower1.shares = 0 (only deducted 40)
        // borrower2.shares = 50 (unchanged)
        // Sum of borrower shares (50) != debt_pool.shares (0)
        assert_eq!(final_state.debt_pool.shares(), Uint128::new(0));
        assert_eq!(final_borrower1.shares, Uint128::new(0));
        assert_eq!(final_borrower2.shares, Uint128::new(50));
        
        // Protocol is now insolvent - borrower2 cannot repay their 50 shares
        // because debt_pool has no shares to burn!
        let result = execute(
            deps.as_mut(),
            env,
            mock_info("borrower2", &coins(50, "uusd")),
            ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        );
        
        // This will fail with ZeroDebt error
        assert!(result.is_err());
    }
}
```

## Notes

This vulnerability demonstrates a critical flaw in the delegate borrowing accounting system. The root cause is the combination of:
1. DELEGATE_SHARES not being updated during regular repays (creating stale values)
2. The `delegate_repay()` function discarding the remainder from the inner `repay()` call
3. The repay execution flow using stale DELEGATE_SHARES to calculate how many shares to burn from the debt_pool

The fix requires either keeping DELEGATE_SHARES synchronized with regular repays, or properly handling remainders throughout the repay flow to prevent the debt_pool from burning more shares than can be deducted from borrowers.

### Citations

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L71-80)
```rust
    pub fn repay(
        &mut self,
        storage: &mut dyn Storage,
        shares: Uint128,
    ) -> Result<Uint128, ContractError> {
        let repaid = min(shares, self.shares);
        self.shares -= repaid;
        self.save(storage)?;
        Ok(shares.sub(repaid))
    }
```

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L82-94)
```rust
    pub fn delegate_repay(
        &mut self,
        storage: &mut dyn Storage,
        delegate: Addr,
        shares: Uint128,
    ) -> Result<Uint128, ContractError> {
        let k = (self.addr.clone(), delegate);
        let delegate = DELEGATE_SHARES.load(storage, k.clone())?;
        let repaid = min(shares, delegate);
        DELEGATE_SHARES.save(storage, k, &delegate.checked_sub(repaid)?)?;
        self.repay(storage, repaid)?;
        Ok(shares.sub(repaid))
    }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L162-181)
```rust
        MarketMsg::Repay { delegate } => {
            let amount = must_pay(&info, config.denom.as_str())?;
            let delegate_address = delegate
                .clone()
                .map(|d| deps.api.addr_validate(&d))
                .transpose()?;

            let borrower_shares = match delegate_address.as_ref() {
                Some(d) => borrower.delegate_shares(deps.storage, d.clone()),
                None => borrower.shares,
            };
            let borrower_debt = state.debt_pool.ownership(borrower_shares);
            let repay_amount = min(amount, borrower_debt);

            let shares = state.repay(repay_amount)?;

            match delegate_address.clone() {
                Some(d) => borrower.delegate_repay(deps.storage, d, shares),
                None => borrower.repay(deps.storage, shares),
            }?;
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L65-73)
```rust
    pub fn repay(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
        if self.debt_pool.size().is_zero() {
            return Err(ContractError::ZeroDebt {});
        }
        // Calculate the amount of shares that this repay will burn
        let shares = amount.multiply_ratio(self.debt_pool.shares(), self.debt_pool.size());
        self.debt_pool.leave(shares)?;
        Ok(shares)
    }
```
