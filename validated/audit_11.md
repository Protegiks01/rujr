# Audit Report

## Title
Integer Division in Share-Based Debt Repayment Causes Transaction Reversion for Small Debt Positions

## Summary
The `repay` function in the rujira-ghost-vault contract uses integer division to calculate shares to burn from repayment amounts. When the debt pool ratio exceeds 1.0 due to interest accrual, borrowers with small debt positions (where `debt < pool_size / pool_shares`) cannot repay because the calculated shares floor to zero, causing `leave(0)` to revert with `SharePoolError::Zero`. This prevents position closure and collateral withdrawal.

## Finding Description

The vulnerability stems from a cascading floor operation across three functions in the repayment flow:

**Step 1: Query calculates displayed debt** [1](#0-0) 

The `ownership()` function floors the debt calculation: [2](#0-1) 

**Step 2: Repay amount is capped at floored debt** [3](#0-2) 

**Step 3: Share calculation floors to zero** [4](#0-3) 

**Step 4: Zero-share burn is rejected** [5](#0-4) 

**Concrete Scenario:**
After interest accrual via `distribute_interest()`: [6](#0-5) 

- debt_pool: size = 1,100, shares = 1,000 (ratio = 1.1)
- User has 1 share
- `ownership(1) = 1,100 * 1 / 1,000 = 1.1 → 1` (floored)
- User sends ANY amount to repay
- `repay_amount = min(amount_sent, 1) = 1`
- `shares_to_burn = 1 * 1,000 / 1,100 = 0.909 → 0` (floored)
- `leave(0)` throws `SharePoolError::Zero`
- **Transaction reverts**

Even if the user sends more tokens, `repay_amount` is capped at the floored `borrower_debt`, so the share calculation still floors to zero.

**Invariant Broken:** Post-Adjustment LTV Check - Users cannot reduce debt to zero to satisfy LTV requirements for collateral withdrawal.

## Impact Explanation

**HIGH Severity** - Temporary Freezing with Economic Loss per Code4rena scope:

1. **Frozen Debt Positions**: Borrowers with debt < (pool_size / pool_shares) cannot execute repay transactions
2. **Collateral Lockup**: LTV constraints prevent collateral withdrawal while any debt exists
3. **Liquidation Risk**: Users face liquidation for debts they attempted but failed to repay
4. **Expanding Scope**: As interest continuously accrues, the minimum repayable amount increases, affecting progressively more users

This is not minor precision loss (<0.01%) but complete transaction failure. The test suite acknowledges this behavior: [7](#0-6) 

However, the workaround (sending more tokens) fails for the final share because `borrower_debt` itself is floored.

## Likelihood Explanation

**HIGH Likelihood:**

- **Inevitable Occurrence**: Interest accrual is continuous and increases pool ratio over time
- **No Attacker**: Natural protocol operation creates the condition
- **Common User Behavior**: Partial repayments and position closures are frequent operations
- **Growing Impact**: The minimum repayable amount increases with each interest distribution

After sufficient time, any borrower with remaining shares where `ownership(shares) < debt_pool.size / debt_pool.shares` will be unable to repay. This is not an edge case but a mathematical certainty given the protocol's interest model.

## Recommendation

Modify the repay logic to handle the final share specially or allow burning shares directly:

```rust
pub fn repay(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
    if self.debt_pool.size().is_zero() {
        return Err(ContractError::ZeroDebt {});
    }
    
    // Calculate shares to burn
    let mut shares = amount.multiply_ratio(self.debt_pool.shares(), self.debt_pool.size());
    
    // If shares round to zero but amount is non-zero, burn 1 share minimum
    if shares.is_zero() && !amount.is_zero() {
        shares = Uint128::one();
    }
    
    self.debt_pool.leave(shares)?;
    Ok(shares)
}
```

Alternatively, allow users to specify shares to burn in the MarketMsg::Repay message.

## Proof of Concept

Add this test to `contracts/rujira-ghost-vault/src/contract.rs`:

```rust
#[test]
fn test_small_debt_repayment_failure() {
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use crate::contract::{execute, instantiate, query, sudo};
    use cw_multi_test::{App, ContractWrapper, Executor};
    
    let mut app = App::default();
    let owner = Addr::unchecked("owner");
    let borrower = Addr::unchecked("borrower");
    
    app.update_block(|block| {
        block.height = 1;
        block.time = Timestamp::from_seconds(1);
    });
    
    app.init_modules(|router, _, storage| {
        router.bank.init_balance(storage, &owner, coins(10_000, "btc")).unwrap();
        router.bank.init_balance(storage, &borrower, coins(10_000, "btc")).unwrap();
    });
    
    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    
    let contract = app.instantiate_contract(
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
                base_rate: Decimal::from_ratio(1u128, 10u128),
                step1: Decimal::from_ratio(1u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            },
            fee: Decimal::zero(),
            fee_address: owner.to_string(),
        },
        &[],
        "vault",
        None,
    ).unwrap();
    
    // Deposit funds
    app.execute_contract(owner.clone(), contract.clone(), &ExecuteMsg::Deposit { callback: None }, &coins(1000, "btc")).unwrap();
    
    // Whitelist borrower
    app.wasm_sudo(contract.clone(), &SudoMsg::SetBorrower { contract: borrower.to_string(), limit: Uint128::from(500u128) }).unwrap();
    
    // Borrow 1 token
    app.execute_contract(borrower.clone(), contract.clone(), &ExecuteMsg::Market(MarketMsg::Borrow { amount: Uint128::one(), callback: None, delegate: None }), &[]).unwrap();
    
    // Advance time to accrue interest
    app.update_block(|b| b.time = b.time.plus_days(365));
    
    // Check debt ratio > 1.0
    let status: StatusResponse = app.wrap().query_wasm_smart(contract.clone(), &QueryMsg::Status {}).unwrap();
    assert!(status.debt_pool.ratio > Decimal::one());
    
    // Query borrower debt - will show floored value
    let borrower_info: BorrowerResponse = app.wrap().query_wasm_smart(contract.clone(), &QueryMsg::Borrower { addr: borrower.to_string() }).unwrap();
    
    // Attempt to repay the displayed debt amount - THIS WILL FAIL
    let result = app.execute_contract(
        borrower.clone(),
        contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        &coins(borrower_info.current.u128(), "btc")
    );
    
    // Assert the transaction failed with SharePoolError::Zero
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Zero") || err_msg.contains("SharePoolError"));
}
```

**Notes**

The vulnerability is exacerbated by the dual flooring: first in `ownership()` when calculating displayed debt, then in `repay()` when calculating shares to burn. Even sending the exact amount shown in queries fails because the share calculation independently floors to zero. The existing test at line 561 shows awareness that users must overpay, but this breaks down completely for the final share of small positions.

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L173-173)
```rust
            let borrower_debt = state.debt_pool.ownership(borrower_shares);
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L174-176)
```rust
            let repay_amount = min(amount, borrower_debt);

            let shares = state.repay(repay_amount)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L561-579)
```rust
        // finally check that a 1:1 repay doesn't work, and that more btc is required

        // debt rate is 1.0325

        let res = app
            .execute_contract(
                borrower.clone(),
                contract.clone(),
                &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
                &[coin(104, "btc")],
            )
            .unwrap();
        res.assert_event(
            &Event::new("wasm-rujira-ghost-vault/repay").add_attributes(vec![
                ("amount", "104"),
                ("borrower", borrower.as_str()),
                ("shares", "100"),
            ]),
        );
```

**File:** packages/rujira-rs/src/share_pool.rs (L37-40)
```rust
    pub fn leave(&mut self, amount: Uint128) -> Result<Uint128, SharePoolError> {
        if amount.is_zero() {
            return Err(SharePoolError::Zero("Amount".to_string()));
        }
```

**File:** packages/rujira-rs/src/share_pool.rs (L74-79)
```rust
    pub fn ownership(&self, shares: Uint128) -> Uint128 {
        if shares.is_zero() {
            return Uint128::zero();
        }
        self.size.multiply_ratio(shares, self.shares())
    }
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

**File:** contracts/rujira-ghost-vault/src/state.rs (L164-164)
```rust
        self.debt_pool.deposit(interest.add(fee))?;
```
