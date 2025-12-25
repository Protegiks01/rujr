# Audit Report

## Title
Precision Loss in Share-Based Debt Repayment Prevents Closure of Small Debt Positions

## Summary
Integer division in the share-to-debt conversion mechanism causes borrowers to become permanently unable to repay small debt positions after interest accrues. The `ownership()` function floors debt calculations while the `repay()` function floors share calculations, creating a mathematical trap where displayed debt rounds to a non-zero value but attempts to repay that amount calculate to zero shares, triggering a transaction revert. This freezes user positions and locks collateral.

## Finding Description

The vulnerability stems from asymmetric rounding in the debt pool's share-based accounting system within `rujira-ghost-vault`.

**Core Mechanism:**

When users query their debt, the system calculates the amount owed using `ownership()` which performs: `debt = pool_size × user_shares ÷ total_shares` with integer division that floors the result. [1](#0-0) 

When users attempt to repay, the system calculates shares to burn using: `shares_to_burn = repay_amount × total_shares ÷ pool_size` with integer division that also floors. [2](#0-1) 

The share pool's `leave()` function explicitly rejects zero-share burns. [3](#0-2) 

**Exploitation Path:**

1. Interest accrues via `distribute_interest()`, which increases `debt_pool.size` without changing `debt_pool.shares`, increasing the size/shares ratio. [4](#0-3) 

2. For a user with 1 share when ratio increases from 1.0 to 1.1:
   - Query shows: `ownership(1) = 1,100,000 × 1 ÷ 1,000,000 = 1.1 → 1` (floored)
   - User attempts to repay 1 unit
   - System calculates: `shares = 1 × 1,000,000 ÷ 1,100,000 = 0.909 → 0` (floored)
   - Call to `leave(0)` reverts with `SharePoolError::Zero`

3. The repay function caps the repayment amount at the displayed debt, preventing workarounds. [5](#0-4) 

**Collateral Lockup Consequence:**

After any account operation including collateral withdrawal, the system enforces an LTV safety check. [6](#0-5) 

The LTV calculation returns zero only when debt is zero. [7](#0-6) 

Therefore, users with unrepayable debt (even 1 unit) cannot reduce their LTV to zero and cannot withdraw all collateral.

**Invariant Violation:**

This breaks **Post-Adjustment LTV Check (Invariant #2)**: Users cannot reduce debt to zero to pass LTV checks for full collateral withdrawal, despite having sufficient assets to repay their displayed debt.

## Impact Explanation

**High Severity - Temporary Freezing with Economic Loss**

1. **Frozen Debt Positions**: Borrowers cannot close positions when their displayed debt is less than the pool's size/shares ratio. This amount starts small but grows continuously as interest accrues.

2. **Collateral Lockup**: The LTV check system prevents full collateral withdrawal while any debt exists. Users with unrepayable debt cannot retrieve their full collateral even though they have sufficient funds for repayment.

3. **Escalating Liquidation Risk**: Users attempting to repay are unable to reduce their debt, leaving them exposed to liquidation if collateral values decline. They face liquidation for debts they actively tried but systemically failed to repay.

4. **Growing Scope**: As the protocol operates and interest continuously accrues, the minimum repayable amount increases. What starts affecting only tiny 1-unit positions will eventually affect progressively larger debt amounts, impacting more users over time.

This is not merely theoretical precision loss (<0.01% accepted risk) - it represents complete transaction failure that prevents normal protocol operations and requires manual intervention or protocol upgrades to resolve.

## Likelihood Explanation

**High Likelihood**

- **Guaranteed Occurrence**: Interest accrual is a core protocol feature that executes on every transaction. The pool ratio inevitably increases over time. [4](#0-3) 

- **No Attacker Required**: This vulnerability manifests through normal protocol operation without any malicious actor. Every `distribute_interest()` call increases the ratio.

- **Widespread Victim Pool**: Any borrower making partial repayments or maintaining small debt positions will eventually encounter this issue as the ratio grows.

- **Natural User Behavior**: Users commonly borrow, partially repay, and attempt to fully close positions - all standard protocol interactions.

## Recommendation

Implement one of the following solutions:

**Option 1: Round-Up Share Calculation in Repay**
```rust
pub fn repay(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
    if self.debt_pool.size().is_zero() {
        return Err(ContractError::ZeroDebt {});
    }
    // Use ceiling division to ensure at least 1 share is burned
    let shares = amount
        .multiply_ratio(self.debt_pool.shares(), self.debt_pool.size())
        .max(Uint128::one()); // Ensure minimum 1 share if amount > 0
    self.debt_pool.leave(shares)?;
    Ok(shares)
}
```

**Option 2: Allow Zero-Share Repayments**
Modify the repay logic to handle the case where calculated shares equal zero by treating it as a successful no-op rather than an error, or by automatically rounding up to 1 share when the repayment amount is non-zero.

**Option 3: Minimum Debt Threshold**
Implement a protocol-level minimum debt amount below which positions are automatically closed, preventing the accumulation of dust debt positions.

## Proof of Concept

```rust
#[test]
fn test_precision_loss_prevents_small_debt_repayment() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let borrower = app.api().addr_make("borrower");
    
    // Initialize balances
    app.init_modules(|router, _, storage| {
        router.bank.init_balance(storage, &owner, coins(1_000_000, "btc")).unwrap();
        router.bank.init_balance(storage, &borrower, coins(1_000_000, "btc")).unwrap();
    });
    
    // Deploy vault with high interest rate to quickly demonstrate the issue
    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    let contract = app.instantiate_contract(
        code_id,
        owner.clone(),
        &InstantiateMsg {
            denom: "btc".to_string(),
            receipt: TokenMetadata::default(),
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(50u128, 100u128), // 50% base rate for fast demonstration
                step1: Decimal::from_ratio(50u128, 100u128),
                step2: Decimal::from_ratio(100u128, 100u128),
            },
            fee: Decimal::zero(),
            fee_address: owner.to_string(),
        },
        &[],
        "vault",
        None,
    ).unwrap();
    
    // Owner deposits large amount to vault
    app.execute_contract(
        owner.clone(),
        contract.clone(),
        &ExecuteMsg::Deposit { callback: None },
        &coins(1_000_000, "btc"),
    ).unwrap();
    
    // Whitelist borrower with small limit
    app.wasm_sudo(contract.clone(), &SudoMsg::SetBorrower {
        contract: borrower.to_string(),
        limit: Uint128::from(10u128),
    }).unwrap();
    
    // Borrower borrows minimal amount (1 unit)
    app.execute_contract(
        borrower.clone(),
        contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Borrow {
            amount: Uint128::one(),
            callback: None,
            delegate: None,
        }),
        &[],
    ).unwrap();
    
    // Advance time to accrue significant interest (increase ratio from 1.0 to >1.1)
    app.update_block(|b| b.time = b.time.plus_seconds(31_536_000)); // 1 year
    
    // Query borrower's debt - should show 1 or 2 units (floored from actual debt)
    let borrower_info: BorrowerResponse = app.wrap()
        .query_wasm_smart(contract.clone(), &QueryMsg::Borrower {
            addr: borrower.to_string(),
        }).unwrap();
    
    let displayed_debt = borrower_info.current;
    assert!(displayed_debt.u128() >= 1); // Debt shown as at least 1
    
    // Attempt to repay the displayed debt amount - THIS SHOULD FAIL
    let repay_result = app.execute_contract(
        borrower.clone(),
        contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        &[coin(displayed_debt.u128(), "btc")],
    );
    
    // Verify the repayment fails with SharePoolError::Zero
    assert!(repay_result.is_err());
    let error = repay_result.unwrap_err().to_string();
    assert!(error.contains("Zero") || error.contains("SharePoolError"));
}
```

## Notes

The vulnerability is particularly insidious because:

1. **Silent Growth**: The minimum unrepayable amount increases gradually and invisibly with each interest accrual, eventually affecting larger positions.

2. **User Confusion**: Users see their debt on-chain queries but cannot repay it, creating confusion and support burden.

3. **No Recovery Path**: Without protocol upgrade or manual intervention by privileged roles, affected users have no way to close their positions.

4. **Cascading Effect**: As interest continues accruing on unrepayable positions, the debt grows while users remain locked out, potentially leading to liquidations.

The distinction from accepted "precision loss <0.01%" is critical: this is not a small rounding error but a complete functional failure that prevents users from executing their intended transactions.

### Citations

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

**File:** contracts/rujira-ghost-vault/src/contract.rs (L169-176)
```rust
            let borrower_shares = match delegate_address.as_ref() {
                Some(d) => borrower.delegate_shares(deps.storage, d.clone()),
                None => borrower.shares,
            };
            let borrower_debt = state.debt_pool.ownership(borrower_shares);
            let repay_amount = min(amount, borrower_debt);

            let shares = state.repay(repay_amount)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L165-169)
```rust
        ExecuteMsg::CheckAccount { addr } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_safe(&config.adjustment_threshold)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L152-176)
```rust
    pub fn adjusted_ltv(&self) -> Decimal {
        let collateral = self
            .collaterals
            .iter()
            .map(|x| x.value_adjusted)
            .collect::<Vec<Decimal>>()
            .into_iter()
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let debt = self
            .debts
            .iter()
            .map(|x| x.value)
            .collect::<Vec<Decimal>>()
            .into_iter()
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        if debt.is_zero() {
            return Decimal::zero();
        }

        debt.div(collateral)
    }
```
