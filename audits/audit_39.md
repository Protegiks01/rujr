# Audit Report

## Title
Precision Loss in Share-Based Debt Repayment Prevents Closure of Small Debt Positions

## Summary
The `ownership()` function's use of `multiply_ratio` with integer division causes precision loss that prevents borrowers from repaying small debt positions. When interest accrues and increases the debt pool's `size/shares` ratio above 1.0, attempts to repay amounts smaller than this ratio result in zero shares being calculated for burning, causing the repayment transaction to fail. This permanently freezes user debt positions and prevents collateral withdrawal. [1](#0-0) 

## Finding Description

The vulnerability exists in the interaction between three key functions:

1. **Query Function** - Calculates displayed debt using `ownership()`: [2](#0-1) 

2. **Repay Function** - Calculates shares to burn based on repayment amount: [3](#0-2) 

3. **Share Pool Ownership** - Uses integer division that floors results: [4](#0-3) 

4. **Share Pool Repay Logic** - Calculates shares to burn: [5](#0-4) 

5. **Leave Function** - Rejects zero-amount burns: [6](#0-5) 

**Exploitation Path:**

When interest accrues via `distribute_interest()`, the debt pool's size increases while shares remain constant, increasing the ratio. Consider:

- Initial: `debt_pool.size = 1,000,000`, `debt_pool.shares = 1,000,000` (ratio = 1.0)
- After interest: `debt_pool.size = 1,100,000`, `debt_pool.shares = 1,000,000` (ratio = 1.1)
- User has 1 share: `ownership(1) = 1,100,000 * 1 / 1,000,000 = 1` (floored from 1.1)
- User attempts to repay 1 unit:
  - `shares_to_burn = 1 * 1,000,000 / 1,100,000 = 0.909... = 0` (floored)
  - Call `leave(0)` → **Error: SharePoolError::Zero**

The transaction reverts, and the user cannot close their position despite having sufficient funds.

**Invariant Broken:** Post-Adjustment LTV Check (Invariant #2) - Users cannot reduce their debt to zero to pass LTV checks for full collateral withdrawal, even when they have sufficient assets to repay.

## Impact Explanation

**High Severity** - Temporary freezing of funds with economic loss:

1. **Frozen Debt Positions**: Borrowers with small remaining debt (< pool ratio) cannot close positions
2. **Collateral Lockup**: LTV constraints prevent full collateral withdrawal while debt exists
3. **Unfair Liquidations**: Users may be liquidated for debts they attempted but failed to repay
4. **Increasing Likelihood**: As interest accrues over time, the pool ratio grows, affecting more users with progressively larger debt amounts

The impact is not just theoretical precision loss <0.01% - it's a complete inability to repay, preventing normal protocol operations. The issue affects real user funds and requires manual intervention or protocol upgrade to resolve.

## Likelihood Explanation

**High Likelihood:**

- **Natural Occurrence**: Interest accrual is a core protocol feature that continuously increases the pool ratio
- **No Attacker Required**: Normal protocol operation creates the vulnerable state
- **Growing Impact**: Over time, the minimum repayable amount increases with the ratio
- **Common User Flow**: Users frequently make partial repayments and attempt to close positions

After sufficient interest accrual, any user with a debt position calculated by `ownership()` that is less than the current pool ratio will be unable to repay. This is not an edge case but an inevitable outcome of the protocol's design.

## Recommendation

Implement special handling in the `repay()` function to allow closing positions when calculated shares round to zero but the borrower has remaining shares:

```rust
pub fn repay(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
    if self.debt_pool.size().is_zero() {
        return Err(ContractError::ZeroDebt {});
    }
    
    let shares = amount.multiply_ratio(self.debt_pool.shares(), self.debt_pool.size());
    
    // Special case: if shares rounds to 0 but we're trying to close a small position,
    // allow burning the remaining dust shares if amount >= ownership of those shares
    let shares_to_burn = if shares.is_zero() && !amount.is_zero() {
        let one_share_value = self.debt_pool.ownership(Uint128::one());
        if amount >= one_share_value {
            Uint128::one()
        } else {
            return Err(ContractError::RepayAmountTooSmall {});
        }
    } else {
        shares
    };
    
    self.debt_pool.leave(shares_to_burn)?;
    Ok(shares_to_burn)
}
```

Additionally, modify the repay flow in `contract.rs` to handle dust positions:

```rust
// In execute_market, before calling state.repay():
let borrower_shares = match delegate_address.as_ref() {
    Some(d) => borrower.delegate_shares(deps.storage, d.clone()),
    None => borrower.shares,
};

// If borrower has very few shares, allow full repayment by paying the ownership value
if borrower_shares <= Uint128::new(10) {
    let full_debt = state.debt_pool.ownership(borrower_shares);
    let repay_amount = min(amount, full_debt);
    // Force burn all shares if paying the full ownership amount
    // ... special handling logic
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_precision_lock {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, Addr, Uint128, Decimal};
    use rujira_rs::ghost::vault::{InstantiateMsg, ExecuteMsg, MarketMsg, Interest};
    use rujira_rs::TokenMetadata;

    #[test]
    fn test_small_debt_cannot_be_repaid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Initialize vault
        let init_msg = InstantiateMsg {
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
            fee_address: "fee_addr".to_string(),
        };
        
        instantiate(deps.as_mut(), env.clone(), mock_info("creator", &[]), init_msg).unwrap();
        
        // Whitelist borrower
        sudo(deps.as_mut(), env.clone(), SudoMsg::SetBorrower {
            contract: "borrower".to_string(),
            limit: Uint128::from(10_000_000u128),
        }).unwrap();
        
        // Initial deposit by lender
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("lender", &coins(1_000_000, "btc")),
            ExecuteMsg::Deposit { callback: None },
        ).unwrap();
        
        // Borrower borrows
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower", &[]),
            ExecuteMsg::Market(MarketMsg::Borrow {
                amount: Uint128::from(500_000u128),
                callback: None,
                delegate: None,
            }),
        ).unwrap();
        
        // Simulate interest accrual (increases size without changing shares)
        let mut state = State::load(deps.as_ref().storage).unwrap();
        state.debt_pool.deposit(Uint128::from(100_000u128)).unwrap();
        state.save(deps.as_mut().storage).unwrap();
        
        // Now debt_pool: size = 600_000, shares = 500_000, ratio = 1.2
        
        // Borrower repays most of the debt
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower", &coins(599_999, "btc")),
            ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        ).unwrap();
        
        // Borrower now has 1 share left
        // ownership(1) = 1 (floors from 1.2)
        
        // Try to repay the last 1 unit - THIS WILL FAIL
        let result = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("borrower", &coins(1, "btc")),
            ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        );
        
        // Assert that the repayment fails due to zero shares
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Zero"));
        
        // Borrower is permanently stuck with 1 share they cannot repay
    }
}
```

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L162-198)
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

            let mut response = Response::default().add_event(event_repay(
                borrower.addr.clone(),
                delegate,
                repay_amount,
                shares,
            ));

            let refund = amount.checked_sub(repay_amount)?;
            if !refund.is_zero() {
                response = response.add_message(BankMsg::Send {
                    to_address: info.sender.to_string(),
                    amount: coins(refund.u128(), &config.denom),
                });
            }
            response
        }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L250-264)
```rust
        QueryMsg::Borrower { addr } => {
            let borrower = Borrower::load(deps.storage, deps.api.addr_validate(&addr)?)?;
            let current = state.debt_pool.ownership(borrower.shares);
            Ok(to_json_binary(&BorrowerResponse {
                addr: borrower.addr.to_string(),
                denom: config.denom,
                limit: borrower.limit,
                current,
                shares: borrower.shares,
                available: min(
                    // Current borrows can exceed limit due to interest
                    borrower.limit.checked_sub(current).unwrap_or_default(),
                    state.deposit_pool.size() - state.debt_pool.size(),
                ),
            })?)
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
