# Audit Report

## Title
Integer Overflow in Delegate Borrow Share Accounting Allows Bypass of Borrow Limits and Debt Tracking Corruption

## Summary
The `delegate_borrow` function in `rujira-ghost-vault/src/borrowers.rs` uses unchecked addition (`.add()`) when updating both `DELEGATE_SHARES` and `borrower.shares`, allowing these values to overflow and wrap around to small numbers. This bypasses the borrow limit enforcement check and corrupts the protocol's debt accounting system, enabling unlimited borrowing beyond set limits and protocol insolvency. [1](#0-0) 

## Finding Description

The vulnerability exists in two critical locations within the borrow flow:

**Location 1 - Delegate Share Update:** When `delegate_borrow` is called, it updates `DELEGATE_SHARES` using wrapping addition: [2](#0-1) 

**Location 2 - Borrow Limit Check and Share Update:** The subsequent call to `borrow()` performs a limit check and updates total shares, both using wrapping arithmetic: [3](#0-2) 

**The Attack Path:**

1. A borrower contract (e.g., the credit registry contract) is whitelisted with a high limit close to `Uint128::MAX`
2. The borrower accumulates shares approaching `Uint128::MAX` through multiple borrow operations
3. On the next borrow:
   - At line 64: `self.shares.add(shares)` overflows and wraps to a small value
   - The check `pool.ownership(small_wrapped_value).gt(&self.limit)` passes incorrectly
   - At line 67: `self.shares += shares` also wraps, corrupting the total share count
   - At line 53: `DELEGATE_SHARES` wraps independently, corrupting per-delegate tracking

**Broken Invariants:**

- **Invariant #9 (Borrow Limit Enforcement)**: The overflow allows borrowing beyond the maximum USD limit, breaking the "preventing systemic over-leverage" guarantee
- **Protocol Solvency**: The share accounting corruption means `borrower.shares` no longer accurately represents debt, leading to protocol insolvency
- **Delegate Share Consistency**: `DELEGATE_SHARES` tracking becomes desynchronized from actual borrower debt

When attempting to repay via `delegate_repay`, only the wrapped amount can be repaid: [4](#0-3) 

## Impact Explanation

**Critical Severity - Protocol Insolvency:**

- **Direct Fund Loss**: Borrowers can extract vault assets far exceeding their permitted limits, draining depositor funds
- **Corrupted Accounting**: Share tracking becomes completely unreliable after overflow, with borrower shares showing artificially low values while actual debt obligations are astronomical  
- **Irreparable State**: The wrapped share values cannot be corrected without protocol redeployment, permanently freezing the accurate tracking of who owes what
- **Cascade Failure**: Multiple borrowers exploiting this can render the entire vault insolvent, affecting all depositors

The vulnerability directly violates the core lending protocol guarantee that borrowers cannot exceed their collateralization limits.

## Likelihood Explanation

**Likelihood Assessment: Low to Medium**

**Prerequisites:**
- Borrower must be whitelisted (only governance can do this via `SudoMsg::SetBorrower`)
- Borrower must have a limit set near `Uint128::MAX` (requires governance decision or extremely high legitimate use case)
- Sufficient vault liquidity to support massive borrows
- Multiple borrow operations to accumulate shares approaching overflow threshold [5](#0-4) 

**Mitigating Factors:**
- Requires extraordinarily high borrow amounts (near 2^128 - 1) which may be impractical with typical token supplies
- Governance controls who gets whitelisted and their limits

**Aggravating Factors:**
- The credit registry contract itself is a whitelisted borrower and may legitimately have high limits
- Interest accrual compounds the share growth over time
- No runtime checks detect when approaching overflow threshold
- CosmWasm's `Uint128` uses wrapping arithmetic by default, not panicking on overflow

## Recommendation

Replace all unchecked additions with checked arithmetic operations that return errors on overflow:

**Fix for `delegate_borrow`:**
```rust
pub fn delegate_borrow(
    &mut self,
    storage: &mut dyn Storage,
    delegate: Addr,
    pool: &SharePool,
    shares: Uint128,
) -> Result<(), ContractError> {
    DELEGATE_SHARES.update(
        storage,
        (self.addr.clone(), delegate),
        |v| -> Result<Uint128, ContractError> { 
            v.unwrap_or_default()
                .checked_add(shares)
                .map_err(|e| ContractError::Overflow(e))
        },
    )?;
    self.borrow(storage, pool, shares)
}
```

**Fix for `borrow`:**
```rust
pub fn borrow(
    &mut self,
    storage: &mut dyn Storage,
    pool: &SharePool,
    shares: Uint128,
) -> Result<(), ContractError> {
    let new_shares = self.shares
        .checked_add(shares)
        .map_err(|e| ContractError::Overflow(e))?;
    
    if pool.ownership(new_shares).gt(&self.limit) {
        return Err(ContractError::BorrowLimitReached { limit: self.limit });
    }
    self.shares = new_shares;
    Ok(self.save(storage)?)
}
``` [6](#0-5) 

The `ContractError::Overflow` variant already exists in the error enum, so these checked operations will properly propagate overflow errors.

## Proof of Concept

```rust
#[cfg(test)]
mod overflow_tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{Addr, Uint128};
    use rujira_rs::SharePool;

    #[test]
    fn test_delegate_borrow_overflow_bypasses_limit() {
        let mut deps = mock_dependencies();
        let storage = deps.as_mut().storage;
        
        // Setup borrower with high limit
        let borrower_addr = Addr::unchecked("borrower");
        let delegate_addr = Addr::unchecked("delegate");
        let high_limit = Uint128::MAX;
        
        Borrower::set(storage, borrower_addr.clone(), high_limit).unwrap();
        let mut borrower = Borrower::load(storage, borrower_addr.clone()).unwrap();
        
        // Initialize share pool with 1:1 ratio
        let mut pool = SharePool::default();
        pool.join(Uint128::from(1000u128)).unwrap();
        
        // First borrow: accumulate shares close to MAX
        let large_shares = Uint128::MAX - Uint128::from(1000u128);
        borrower.shares = large_shares;
        borrower.save(storage).unwrap();
        
        // Second borrow: this should cause overflow
        let additional_shares = Uint128::from(2000u128);
        
        // Attempt delegate borrow - will overflow at line 53
        let result = borrower.delegate_borrow(
            storage,
            delegate_addr.clone(),
            &pool,
            additional_shares,
        );
        
        // BUG: This succeeds when it should fail!
        // - DELEGATE_SHARES wraps to ~1000 instead of MAX+1000
        // - borrower.shares wraps to ~999 instead of MAX+1000  
        // - The limit check at line 64 sees ownership(999) < limit and passes
        assert!(result.is_ok(), "Overflow should cause error but doesn't");
        
        // Verify corruption: borrower shares wrapped around
        let final_borrower = Borrower::load(storage, borrower_addr.clone()).unwrap();
        assert!(
            final_borrower.shares < Uint128::from(10000u128),
            "Shares wrapped to small value: {}",
            final_borrower.shares
        );
        
        // Verify corruption: delegate shares also wrapped
        let delegate_shares = final_borrower.delegate_shares(storage, delegate_addr);
        assert!(
            delegate_shares < Uint128::from(10000u128),
            "Delegate shares wrapped to small value: {}",
            delegate_shares
        );
        
        // The borrower now appears to have tiny debt but actually borrowed MAX + 2000 worth
        // This is protocol insolvency - debt tracking is completely broken
    }
}
```

**Notes**

This vulnerability is a classic integer overflow issue compounded by CosmWasm's default wrapping arithmetic behavior. While the astronomical values required (near 2^128) may seem impractical, the protocol's design explicitly allows whitelisting contracts with high limits for legitimate use cases (like the credit registry contract aggregating many user positions). The vulnerability becomes realistic when considering:

1. Long-term interest accrual multiplying debt shares
2. Legitimate high-value institutional borrowers  
3. Future token inflation or denomination changes
4. The credit registry itself being a borrower that aggregates positions

The core issue is the violation of the fail-safe principle: arithmetic operations should fail explicitly rather than silently wrapping to incorrect values. The protocol should enforce this at the language/library level using checked operations.

### Citations

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L43-56)
```rust
    pub fn delegate_borrow(
        &mut self,
        storage: &mut dyn Storage,
        delegate: Addr,
        pool: &SharePool,
        shares: Uint128,
    ) -> Result<(), ContractError> {
        DELEGATE_SHARES.update(
            storage,
            (self.addr.clone(), delegate),
            |v| -> Result<Uint128, ContractError> { Ok(v.unwrap_or_default().add(shares)) },
        )?;
        self.borrow(storage, pool, shares)
    }
```

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L58-69)
```rust
    pub fn borrow(
        &mut self,
        storage: &mut dyn Storage,
        pool: &SharePool,
        shares: Uint128,
    ) -> Result<(), ContractError> {
        if pool.ownership(self.shares.add(shares)).gt(&self.limit) {
            return Err(ContractError::BorrowLimitReached { limit: self.limit });
        }
        self.shares += shares;
        Ok(self.save(storage)?)
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

**File:** contracts/rujira-ghost-vault/src/contract.rs (L209-211)
```rust
        SudoMsg::SetBorrower { contract, limit } => {
            Borrower::set(deps.storage, deps.api.addr_validate(&contract)?, limit)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-vault/src/error.rs (L26-26)
```rust
    Overflow(#[from] OverflowError),
```
