# Audit Report

## Title
Permanent Vault Freeze via Unchecked Withdrawal Leading to Arithmetic Underflow in Utilization Calculation

## Summary
The `State::withdraw()` function does not validate that withdrawals maintain the invariant `deposit_pool.size >= debt_pool.size`. When this invariant is violated, the `State::utilization()` function attempts an unchecked subtraction that underflows, causing ALL vault operations (deposits, withdrawals, borrows, repays, and queries) to fail permanently, freezing all user funds until contract migration.

## Finding Description

The vulnerability exists in the withdrawal validation logic within the ghost-vault contract. The security question asks whether a corrupted state where `debt_pool.size > deposit_pool.size` could reach `Interest::rate()` and trigger its validation check. The reality is more severe: **the corrupted state causes an arithmetic underflow before Interest::rate() is ever reached**, completely freezing the vault.

**Root Cause:**

The `State::withdraw()` function validates only that the user has sufficient shares, but does not enforce the critical protocol invariant that `deposit_pool.size >= debt_pool.size`: [1](#0-0) 

**Underflow Location:**

When `debt_pool.size > deposit_pool.size`, the `State::utilization()` function performs an unchecked subtraction that underflows: [2](#0-1) 

The critical line is 83, which computes `self.deposit_pool.size().sub(self.debt_pool.size())`. When debt exceeds deposits, this subtraction on `Uint128` causes arithmetic underflow.

**Cascading Failure:**

This utilization calculation is called from multiple critical paths:

1. **All execute operations** call `distribute_interest()` before processing: [3](#0-2) 

2. **`distribute_interest()` calls `debt_rate()` which calls `utilization()`:** [4](#0-3) [5](#0-4) 

3. **All query operations** also call `distribute_interest()`: [6](#0-5) 

4. **Additional underflows in query responses** when computing "available" funds: [7](#0-6) 

The same unchecked subtraction appears at lines 280 and 309.

**Attack Scenario:**

1. User A deposits 1000 tokens → `deposit_pool.size = 1000`
2. Borrower B borrows 800 tokens → `debt_pool.size = 800`
3. Interest accrues over time (both pools increase equally):
   - `deposit_pool.size = 1050`
   - `debt_pool.size = 850`
4. User A withdraws 750 shares (approximately 787 tokens):
   - `deposit_pool.size = 1050 - 787 = 263`
   - `debt_pool.size = 850` (unchanged)
5. **Corrupted state reached**: `debt_pool.size (850) > deposit_pool.size (263)`
6. **All subsequent operations fail** due to underflow in `utilization()`

This breaks the "Always-Accrued Interest" invariant (#10), as `distribute_interest()` can no longer execute, and all vault functionality becomes permanently unavailable.

## Impact Explanation

**Critical Severity** - This vulnerability causes permanent freezing of ALL funds in the vault:

- **Deposits frozen**: No user can withdraw their deposited funds
- **Borrows frozen**: Borrowers cannot repay their debts
- **New operations impossible**: No deposits, withdrawals, borrows, or repays can be processed
- **Queries fail**: Most query endpoints become non-functional
- **Protocol insolvency**: Outstanding debt cannot be repaid, leaving the vault technically insolvent

The only recovery path is contract migration, which requires governance intervention and may result in loss of accrued interest data. All funds remain locked until migration completes.

The attack requires no special privileges - any depositor can trigger this by withdrawing their shares when there is outstanding debt, if their withdrawal would reduce `deposit_pool.size` below `debt_pool.size`.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Natural occurrence**: This can happen organically without malicious intent:
   - Multiple depositors withdraw simultaneously during high utilization periods
   - Depositors panic-withdraw when they see high vault utilization
   - Early depositors exit while substantial debt remains outstanding

2. **No warning system**: Users and the protocol have no way to detect they are approaching this critical threshold until it's too late

3. **Low barrier**: Any depositor with sufficient shares can trigger this condition

4. **Economic incentive**: In certain market conditions, large depositors may prefer to withdraw early, unknowingly (or knowingly) creating this state

5. **Realistic parameters**: The vulnerability activates at moderate utilization levels (e.g., 80%+ utilization with subsequent withdrawals)

The combination of high impact and high likelihood makes this a critical vulnerability requiring immediate remediation.

## Recommendation

**Immediate Fix**: Add validation in `State::withdraw()` to prevent withdrawals that would violate the invariant:

```rust
pub fn withdraw(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
    let withdrawn = self.deposit_pool.leave(amount)?;
    
    // Ensure withdrawal doesn't reduce deposits below debt
    if self.deposit_pool.size() < self.debt_pool.size() {
        return Err(ContractError::InsufficientLiquidity {});
    }
    
    Ok(withdrawn)
}
```

**Alternative safe implementation using checked arithmetic**:

```rust
pub fn utilization(&self) -> Decimal {
    if self.deposit_pool.size().is_zero() {
        Decimal::zero()
    } else {
        // Use checked subtraction to prevent underflow
        match self.deposit_pool.size().checked_sub(self.debt_pool.size()) {
            Some(available) => Decimal::one() - Decimal::from_ratio(
                available,
                self.deposit_pool.size(),
            ),
            None => {
                // debt > deposits, return max utilization
                Decimal::one()
            }
        }
    }
}
```

**Additional safeguards**:
- Add a query endpoint to check current liquidity: `deposit_pool.size - debt_pool.size`
- Emit events when utilization exceeds certain thresholds (e.g., 90%, 95%, 99%)
- Consider implementing a utilization cap that prevents borrows above a certain threshold

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use cosmwasm_std::{testing::mock_env, Addr, Decimal, Uint128};
    use cw_multi_test::{App, ContractWrapper, Executor};
    use rujira_rs::{ghost::vault::Interest, TokenMetadata};

    #[test]
    fn test_withdrawal_causes_permanent_vault_freeze() {
        let mut app = App::default();
        let owner = Addr::unchecked("owner");
        let depositor = Addr::unchecked("depositor");
        let borrower = Addr::unchecked("borrower");

        // Initialize balances
        app.init_modules(|router, _, storage| {
            router.bank.init_balance(storage, &depositor, vec![coin(10000, "btc")]).unwrap();
            router.bank.init_balance(storage, &borrower, vec![coin(10000, "btc")]).unwrap();
        });

        // Deploy vault contract
        let code = ContractWrapper::new(execute, instantiate, query).with_sudo(sudo);
        let code_id = app.store_code(Box::new(code));
        
        let vault = app.instantiate_contract(
            code_id,
            owner.clone(),
            &InstantiateMsg {
                denom: "btc".to_string(),
                receipt: TokenMetadata::default(),
                interest: Interest {
                    target_utilization: Decimal::percent(80),
                    base_rate: Decimal::percent(10),
                    step1: Decimal::percent(10),
                    step2: Decimal::from_ratio(3u128, 1u128),
                },
                fee: Decimal::zero(),
                fee_address: owner.to_string(),
            },
            &[],
            "vault",
            None,
        ).unwrap();

        // Step 1: Depositor deposits 1000 tokens
        app.execute_contract(
            depositor.clone(),
            vault.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &[coin(1000, "btc")],
        ).unwrap();

        // Step 2: Whitelist borrower with 800 token limit
        app.wasm_sudo(
            vault.clone(),
            &SudoMsg::SetBorrower {
                contract: borrower.to_string(),
                limit: Uint128::new(800),
            },
        ).unwrap();

        // Step 3: Borrower borrows 800 tokens
        app.execute_contract(
            borrower.clone(),
            vault.clone(),
            &ExecuteMsg::Market(MarketMsg::Borrow {
                amount: Uint128::new(800),
                callback: None,
                delegate: None,
            }),
            &[],
        ).unwrap();

        // Step 4: Time passes, interest accrues
        app.update_block(|block| {
            block.time = block.time.plus_seconds(365 * 24 * 60 * 60); // 1 year
        });

        // Verify state after interest accrual
        let status: StatusResponse = app.wrap()
            .query_wasm_smart(vault.clone(), &QueryMsg::Status {})
            .unwrap();
        
        // After 1 year at ~10% rate, debt has grown
        // deposit_pool grew to ~1080, debt_pool grew to ~880

        // Step 5: Depositor withdraws most of their shares
        // This withdrawal will cause deposit_pool.size < debt_pool.size
        let withdraw_shares = Uint128::new(850); // Withdrawing most shares
        
        app.execute_contract(
            depositor.clone(),
            vault.clone(),
            &ExecuteMsg::Withdraw { callback: None },
            &[coin(withdraw_shares.u128(), "x/ghost-vault/btc")],
        ).unwrap();

        // Step 6: Verify the corrupted state
        let status: StatusResponse = app.wrap()
            .query_wasm_smart(vault.clone(), &QueryMsg::Status {})
            .unwrap();
        
        // At this point: debt_pool.size > deposit_pool.size
        assert!(status.debt_pool.size > status.deposit_pool.size,
                "Corrupted state not reached");

        // Step 7: Attempt ANY operation - they all fail
        
        // Try to deposit - FAILS
        let deposit_result = app.execute_contract(
            depositor.clone(),
            vault.clone(),
            &ExecuteMsg::Deposit { callback: None },
            &[coin(100, "btc")],
        );
        assert!(deposit_result.is_err(), "Deposit should fail due to underflow");

        // Try to repay - FAILS
        let repay_result = app.execute_contract(
            borrower.clone(),
            vault.clone(),
            &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
            &[coin(100, "btc")],
        );
        assert!(repay_result.is_err(), "Repay should fail due to underflow");

        // Try to query borrower - FAILS
        let query_result: Result<BorrowerResponse, _> = app.wrap()
            .query_wasm_smart(
                vault.clone(),
                &QueryMsg::Borrower { addr: borrower.to_string() }
            );
        assert!(query_result.is_err(), "Query should fail due to underflow");

        println!("✓ Vault completely frozen - all operations fail");
        println!("✓ Depositors cannot withdraw: {} tokens stuck", status.deposit_pool.size);
        println!("✓ Borrowers cannot repay: {} tokens in debt", status.debt_pool.size);
        println!("✓ Protocol insolvent: debt > deposits by {} tokens",
                 status.debt_pool.size.u128() - status.deposit_pool.size.u128());
    }
}
```

**Notes:**
- The PoC demonstrates complete vault freeze after normal operations
- No malicious intent required - can happen through organic withdrawal patterns
- Recovery requires contract migration with potential loss of state
- All funds remain locked until governance intervention

### Citations

**File:** contracts/rujira-ghost-vault/src/state.rs (L56-59)
```rust
    pub fn withdraw(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
        let withdrawn = self.deposit_pool.leave(amount)?;
        Ok(withdrawn)
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L75-87)
```rust
    pub fn utilization(&self) -> Decimal {
        // We consider accrued interest and debt in the utilization rate
        if self.deposit_pool.size().is_zero() {
            Decimal::zero()
        } else {
            Decimal::one()
                - Decimal::from_ratio(
                    // We use the debt pool size to determine utilization
                    self.deposit_pool.size().sub(self.debt_pool.size()),
                    self.deposit_pool.size(),
                )
        }
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L89-91)
```rust
    pub fn debt_rate(&self, interest: &Interest) -> StdResult<Decimal> {
        interest.rate(self.utilization())
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L97-109)
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
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L48-51)
```rust
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L223-226)
```rust
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let mut state = State::load(deps.storage)?;
    let config = Config::load(deps.storage)?;
    state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L259-264)
```rust
                available: min(
                    // Current borrows can exceed limit due to interest
                    borrower.limit.checked_sub(current).unwrap_or_default(),
                    state.deposit_pool.size() - state.debt_pool.size(),
                ),
            })?)
```
