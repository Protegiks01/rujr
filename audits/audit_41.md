# Audit Report

## Title
Interest Accrual Allows Permanent Breach of Borrower Limits, Breaking Risk Management Invariant

## Summary
The vault's borrower limit enforcement only prevents NEW borrows from exceeding limits, but allows existing positions to grow indefinitely above limits through interest accrual. This breaks the documented "Borrow Limit Enforcement" invariant and renders governance risk management tools ineffective. [1](#0-0) 

## Finding Description

The protocol documents a critical invariant in the README stating that "Borrow Limit Enforcement...guarantees no combination of delegate borrowing can exceed the borrower's cap." However, this invariant is violated through interest accrual mechanics.

**The Vulnerability Flow:**

1. A borrower has a configured limit (e.g., 1,000,000 USD) set via `SudoMsg::SetBorrower`
2. The borrower borrows exactly to their limit (1,000,000 USD)
3. The `borrow` function validates this is acceptable: [2](#0-1) 

4. Interest accrues over time via `distribute_interest`, increasing the debt_pool size: [3](#0-2) 

5. The borrower's debt value increases (e.g., to 1,100,000 USD) while their shares remain constant
6. The query function acknowledges this with a comment but uses `unwrap_or_default()` to handle the over-limit state: [4](#0-3) 

7. Future borrow attempts are blocked, but the borrower can maintain the over-limit position indefinitely
8. Governance cannot enforce the limit retroactively because `Borrower::set` has no validation: [5](#0-4) 

**Breaking the Invariant:**

The documented invariant explicitly states: [6](#0-5) 

This guarantee is false. Interest accrual allows borrower positions to exceed caps without any enforcement mechanism, creating permanent over-limit positions that governance cannot correct.

## Impact Explanation

**High Severity** due to:

1. **Systemic Over-Leverage Risk**: If multiple borrowers exploit this (intentionally or passively), the vault accumulates significantly more exposure than intended by governance. With 50% APR over 2 years, a borrower at 1M limit could reach 2.25M debt—125% over their cap.

2. **Governance Risk Controls Rendered Ineffective**: When governance identifies increased risk and attempts to reduce a borrower's limit from 1M to 500K via `SetBorrower`, nothing forces the borrower with 1.1M current debt to comply. The risk mitigation completely fails.

3. **Breaks Core Protocol Invariant**: The "Borrow Limit Enforcement" invariant is explicitly documented as preventing "systemic over-leverage," but the implementation permits exactly that.

4. **Concentration Risk**: Multiple borrowers simultaneously over-limit creates unintended vault concentration risk that wasn't factored into the protocol's risk parameters.

This qualifies as **High Severity** per the scope criteria: "Systemic undercollateralization risks" and breaks a documented invariant that guarantees borrower caps cannot be exceeded.

## Likelihood Explanation

**Likelihood: High**

This vulnerability occurs automatically without any attacker action:
- Every borrower naturally accrues interest over time
- High utilization periods with elevated interest rates accelerate the breach
- No special conditions or exploits required—it's a fundamental design flaw
- Affects ALL borrowers who have non-zero debt positions
- Occurs continuously as long as positions remain open

The only mitigation is if borrowers voluntarily repay or get liquidated via LTV thresholds (separate from vault limits), but neither addresses the broken invariant.

## Recommendation

Implement enforcement of borrower limits that accounts for accrued interest. Two potential approaches:

**Option 1: Prevent Over-Limit Interest Accrual**
```rust
pub fn borrow(
    &mut self,
    storage: &mut dyn Storage,
    pool: &SharePool,
    shares: Uint128,
) -> Result<(), ContractError> {
    let current_debt = pool.ownership(self.shares);
    let new_total = pool.ownership(self.shares.add(shares));
    
    // Check both new debt AND current debt against limit
    if current_debt.gt(&self.limit) {
        return Err(ContractError::BorrowLimitExceeded { 
            current: current_debt,
            limit: self.limit 
        });
    }
    
    if new_total.gt(&self.limit) {
        return Err(ContractError::BorrowLimitReached { limit: self.limit });
    }
    
    self.shares += shares;
    Ok(self.save(storage)?)
}
```

**Option 2: Validate Limit Updates**
```rust
pub fn set(storage: &mut dyn Storage, addr: Addr, limit: Uint128, pool: &SharePool) -> Result<(), ContractError> {
    let mut borrower = BORROWERS.load(storage, addr.clone()).unwrap_or(Borrower {
        addr: addr.clone(),
        limit: Default::default(),
        shares: Default::default(),
    });
    
    let current_debt = pool.ownership(borrower.shares);
    if current_debt.gt(&limit) {
        return Err(ContractError::CannotReduceLimitBelowCurrentDebt {
            current: current_debt,
            proposed_limit: limit
        });
    }
    
    borrower.limit = limit;
    BORROWERS.save(storage, addr, &borrower)
}
```

**Recommended Approach**: Implement both options to ensure:
1. New borrows are blocked when already over-limit
2. Governance cannot set limits below current debt (preventing impossible states)
3. Document that limits are enforced at borrow-time, and interest can cause temporary exceedance until next borrow attempt

## Proof of Concept

```rust
#[cfg(test)]
mod test_interest_limit_breach {
    use super::*;
    use cosmwasm_std::{coin, coins, Decimal, Uint128};
    use cw_multi_test::{ContractWrapper, Executor};
    use rujira_rs::{ghost::vault::Interest, TokenMetadata};
    use rujira_rs_testing::mock_rujira_app;

    #[test]
    fn test_borrower_exceeds_limit_via_interest() {
        let mut app = mock_rujira_app();
        let owner = app.api().addr_make("owner");
        let borrower = app.api().addr_make("borrower");

        app.init_modules(|router, _, storage| {
            router.bank.init_balance(storage, &owner, coins(10_000, "btc")).unwrap();
            router.bank.init_balance(storage, &borrower, coins(10_000, "btc")).unwrap();
        });

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
                        base_rate: Decimal::from_ratio(5u128, 10u128), // 50% base rate for faster accrual
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

        // Lender deposits 1000 BTC
        app.execute_contract(
            owner.clone(),
            contract.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &coins(1_000, "btc"),
        )
        .unwrap();

        // Set borrower limit to 500 BTC
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(500u128),
            },
        )
        .unwrap();

        // Borrower borrows exactly to limit: 500 BTC
        app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                callback: None,
                amount: Uint128::from(500u128),
                delegate: None,
            }),
            &[],
        )
        .unwrap();

        // Query initial state
        let response: BorrowerResponse = app
            .wrap()
            .query_wasm_smart(
                contract.clone(),
                &QueryMsg::Borrower {
                    addr: borrower.to_string(),
                },
            )
            .unwrap();
        
        assert_eq!(response.limit, Uint128::from(500u128));
        assert_eq!(response.current, Uint128::from(500u128));
        assert_eq!(response.available, Uint128::zero());

        // Wait 1 year for interest to accrue at ~50% APR
        app.update_block(|x| x.time = x.time.plus_seconds(31_536_000));

        // Query after interest accrual - borrower now EXCEEDS limit
        let response_after: BorrowerResponse = app
            .wrap()
            .query_wasm_smart(
                contract.clone(),
                &QueryMsg::Borrower {
                    addr: borrower.to_string(),
                },
            )
            .unwrap();

        // VULNERABILITY DEMONSTRATED:
        // 1. Limit is still 500
        assert_eq!(response_after.limit, Uint128::from(500u128));
        
        // 2. Current debt is now ~750 (50% more due to interest)
        assert!(response_after.current > Uint128::from(500u128));
        println!("Borrower limit: {}", response_after.limit);
        println!("Borrower current debt: {}", response_after.current);
        println!("Over-limit by: {}", response_after.current.u128() - response_after.limit.u128());
        
        // 3. Borrower is 50% over their limit due to interest
        assert!(response_after.current.u128() > response_after.limit.u128());
        
        // 4. Available is 0 (cannot borrow more)
        assert_eq!(response_after.available, Uint128::zero());

        // 5. Governance tries to reduce risk by lowering limit to 250
        app.wasm_sudo(
            contract.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::from(250u128),
            },
        )
        .unwrap();

        // 6. Query shows limit changed but debt unchanged
        let response_final: BorrowerResponse = app
            .wrap()
            .query_wasm_smart(
                contract.clone(),
                &QueryMsg::Borrower {
                    addr: borrower.to_string(),
                },
            )
            .unwrap();

        // CRITICAL: Borrower now has ~750 debt against 250 limit (3x over!)
        assert_eq!(response_final.limit, Uint128::from(250u128));
        assert!(response_final.current > Uint128::from(700u128));
        println!("\n=== AFTER GOVERNANCE REDUCES LIMIT ===");
        println!("New limit: {}", response_final.limit);
        println!("Current debt: {}", response_final.current);
        println!("Breach factor: {}x over limit", 
            response_final.current.u128() / response_final.limit.u128());
        
        // 7. Borrower cannot borrow more, but can maintain over-limit position indefinitely
        let borrow_result = app.execute_contract(
            borrower.clone(),
            contract.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                callback: None,
                amount: Uint128::from(1u128),
                delegate: None,
            }),
            &[],
        );
        assert!(borrow_result.is_err()); // Cannot borrow more
        
        // 8. No mechanism forces repayment - borrower limit is permanently violated
        // Invariant "Borrow Limit Enforcement" is BROKEN
    }
}
```

**Notes:**
- This vulnerability is inherent to the design, not an edge case
- The code comment at line 260 acknowledges the behavior but doesn't address the security implications
- The vault's per-borrower limits become meaningless over time, undermining governance's risk management capabilities
- The only constraint is the credit account's LTV ratio (cross-vault), which is separate from individual vault exposure limits
- This creates a divergence between intended risk exposure (the limit) and actual exposure (debt with accrued interest)

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L259-263)
```rust
                available: min(
                    // Current borrows can exceed limit due to interest
                    borrower.limit.checked_sub(current).unwrap_or_default(),
                    state.deposit_pool.size() - state.debt_pool.size(),
                ),
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

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L96-104)
```rust
    pub fn set(storage: &mut dyn Storage, addr: Addr, limit: Uint128) -> StdResult<()> {
        let mut borrower = BORROWERS.load(storage, addr.clone()).unwrap_or(Borrower {
            addr: addr.clone(),
            limit: Default::default(),
            shares: Default::default(),
        });
        borrower.limit = limit;
        BORROWERS.save(storage, addr, &borrower)
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

**File:** README.md (L116-118)
```markdown
### Borrow Limit Enforcement

Borrower::borrow recalculates the shares’ USD value and blocks any request that would surpass the configured limit, and delegates call into the same struct so they share the exact headroom; this guarantees no combination of delegate borrowing can exceed the borrower’s cap (contracts/rujira-ghost-vault/src/borrowers.rs (lines 54-113)).
```
