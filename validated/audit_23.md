# Audit Report

## Title
Division by Zero Panic in `adjusted_ltv()` Permanently Bricks Accounts with Zero-Valued Collateral and Non-Zero Debt

## Summary
The `adjusted_ltv()` function in `rujira-ghost-credit` performs unchecked division by collateral value, causing a transaction panic when an account has non-zero debt but zero-valued collateral. This permanently freezes the account and makes the debt unrecoverable by the protocol.

## Finding Description

The vulnerability exists in the `adjusted_ltv()` function which calculates the loan-to-value ratio by dividing total debt by total collateral value. The function performs unchecked division without validating that the collateral value is non-zero. [1](#0-0) 

The critical flaw manifests through the following execution sequence:

**Step 1: Collateral Filtering During Account Load**

When an account is loaded via `to_credit_account()`, the function iterates through configured collateral denoms and filters out any collateral with zero USD value. [2](#0-1) 

This filtering occurs when:
- Oracle prices drop to zero or near-zero values
- Dust collateral amounts calculate to zero USD value after decimal arithmetic
- Any condition where `item.value_usd(deps.querier)?.is_zero()` returns true

**Step 2: Asymmetric Debt Handling**

Debt positions are only filtered if their value is zero. [3](#0-2) 

This creates an asymmetry: all zero-valued collateral is excluded, but non-zero debt remains.

**Step 3: Division by Zero in LTV Calculation**

In `adjusted_ltv()`, when `self.collaterals` is empty, the reduce operation returns `Decimal::zero()`. [4](#0-3) 

The function only performs an early return if debt is zero, not if collateral is zero. [5](#0-4) 

When debt is non-zero and collateral is zero, the unchecked division operation `debt.div(collateral)` triggers a panic. [1](#0-0) 

**Step 4: Widespread Impact Across Critical Paths**

The `adjusted_ltv()` function is called in multiple critical code paths:

1. **Account Operations**: After any `ExecuteMsg::Account` operation, the `CheckAccount` message is appended, which loads the account and calls `check_safe()` that invokes `adjusted_ltv()`. [6](#0-5) [7](#0-6) 

2. **Liquidation Initiation**: When a liquidator calls `ExecuteMsg::Liquidate`, the function loads the account and calls `check_unsafe()` which invokes `adjusted_ltv()`. [8](#0-7) [9](#0-8) 

3. **Query Operations**: All account queries convert the `CreditAccount` to `AccountResponse`, which calls `adjusted_ltv()` in the conversion. [10](#0-9) 

**Security Invariant Violations**

This breaks **Critical Invariant #2** (Post-Adjustment LTV Check) and **Critical Invariant #3** (Safe Liquidation Outcomes) because `adjusted_ltv()` cannot return a value to compare against thresholds—it panics instead, preventing any validation or liquidation logic from executing.

**Code Inconsistency**

The codebase uses safe division elsewhere. For example, in the same file, `validate_liquidation()` uses `checked_div()` for safe division with proper handling of division by zero. [11](#0-10) 

The use of `std::ops::Div` is explicitly imported for the unsafe division operation. [12](#0-11) 

## Impact Explanation

**Severity: Critical**

This vulnerability results in:

1. **Permanent Freezing of Funds**: Once triggered, the account becomes completely inaccessible. The owner cannot perform any operations because all `ExecuteMsg::Account` calls append a `CheckAccount` message that panics. Liquidators cannot liquidate the position because `ExecuteMsg::Liquidate` panics during the `check_unsafe()` call. Even queries fail because the `AccountResponse` conversion panics.

2. **Direct Loss of Funds**: The protocol loses the entire outstanding debt amount. Since no transaction can successfully execute against the bricked account, the debt becomes permanently unrecoverable. The collateral (even if it later regains value) remains locked, and the debt cannot be repaid or liquidated.

3. **Protocol Insolvency Risk**: If multiple accounts are affected during market volatility (e.g., multiple assets experiencing oracle price crashes simultaneously), the protocol accumulates significant unrecoverable bad debt, threatening overall protocol solvency.

This qualifies as **Critical** under Code4rena criteria because it causes:
- "Permanent freezing of funds (fix requires protocol redeployment)"
- "Direct loss of funds (protocol assets)" through unrecoverable debt

**Quantification:**
- Each affected account: Full debt value is lost (potentially hundreds of thousands of dollars)
- Protocol-wide: Sum of all unrecoverable debt across affected accounts
- User impact: Complete loss of account access and inability to manage positions

## Likelihood Explanation

**Likelihood: High**

This vulnerability has high likelihood because:

1. **No Attacker Required**: The vulnerability can be triggered by external market conditions without any malicious actor. During extreme market volatility or oracle malfunctions, asset prices can legitimately drop to zero or near-zero values.

2. **Multiple Trigger Scenarios**:
   - **Oracle Price Crashes**: Legitimate black swan events or oracle failures causing prices to drop to zero
   - **Dust Accumulation**: Normal protocol operations (withdrawals, swaps) can leave dust amounts that, when multiplied by low prices, round to zero USD value
   - **Precision Arithmetic**: Very small oracle prices (e.g., 0.0000001 USD) multiplied by small collateral amounts can result in zero after Decimal arithmetic

3. **Common Preconditions**:
   - Account must have non-zero debt (extremely common state after borrowing)
   - Collateral USD value must become zero (realistic during market crashes or with dust amounts)

4. **Affects Core Protocol Functionality**: Every account operation, liquidation attempt, and query that involves the affected account will fail, making this a critical operational failure.

5. **External Factor Dependency**: The vulnerability is triggered by factors outside user or protocol control (oracle prices, market conditions), making it more likely to occur than exploits requiring deliberate attacker actions.

The likelihood is **High** because it can occur naturally through market dynamics, affects fundamental protocol operations, and requires no special privileges or complex attack vectors.

## Recommendation

Replace the unchecked division with safe division that handles the zero collateral case:

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

    // Add check for zero collateral
    if collateral.is_zero() {
        return Decimal::MAX; // Or handle as infinite LTV
    }

    debt.checked_div(collateral).unwrap_or(Decimal::MAX)
}
```

Alternatively, prevent accounts from reaching the invalid state by:
1. Requiring minimum collateral value thresholds
2. Automatically liquidating accounts before collateral value reaches zero
3. Preventing operations that would result in zero-valued collateral with outstanding debt

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Create an account with collateral (e.g., 1000 USDC worth $1000)
2. Borrow against it (e.g., 500 USDC, LTV = 0.5)
3. Simulate oracle price dropping to zero or withdrawing collateral to dust amounts
4. Attempt any account operation, liquidation, or query
5. Transaction panics at the `adjusted_ltv()` division

A full Rust test would require mocking the oracle to return zero prices for the collateral denom, then calling any of the affected operations (CheckAccount, Liquidate, or Account query). The test would verify that the transaction panics with a division by zero error rather than returning a valid LTV value or error.

**Notes**

This is a critical edge case that violates the protocol's safety invariants. The asymmetric handling of zero-valued collateral (filtered out) versus zero-valued debt (kept) creates a state where the LTV calculation becomes mathematically undefined. The protocol should either prevent this state from occurring or handle it gracefully with checked arithmetic, as demonstrated by the `checked_div` usage elsewhere in the same codebase.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L15-15)
```rust
use std::ops::{Add, Div};
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L153-160)
```rust
        let collateral = self
            .collaterals
            .iter()
            .map(|x| x.value_adjusted)
            .collect::<Vec<Decimal>>()
            .into_iter()
            .reduce(|a, b| a + b)
            .unwrap_or_default();
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L171-173)
```rust
        if debt.is_zero() {
            return Decimal::zero();
        }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L175-175)
```rust
        debt.div(collateral)
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L178-186)
```rust
    pub fn check_safe(&self, limit: &Decimal) -> Result<(), ContractError> {
        ensure!(
            self.adjusted_ltv().lt(limit),
            ContractError::Unsafe {
                ltv: self.adjusted_ltv()
            }
        );
        Ok(())
    }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L188-191)
```rust
    pub fn check_unsafe(&self, limit: &Decimal) -> Result<(), ContractError> {
        ensure!(self.adjusted_ltv().ge(limit), ContractError::Safe {});
        Ok(())
    }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L266-270)
```rust
        let slippage = spent_usd
            .checked_sub(repaid_usd)
            .unwrap_or_default()
            .checked_div(spent_usd)
            .unwrap_or_default();
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L300-309)
```rust
        for denom in config.collateral_ratios.keys() {
            let item = Collateral::try_from(&deps.querier.query_balance(&self.account, denom)?)?;
            if item.value_usd(deps.querier)?.is_zero() {
                continue;
            }
            ca.collaterals.push(Valued {
                value: item.value_usd(deps.querier)?,
                value_adjusted: item.value_adjusted(deps, &config.collateral_ratios)?,
                item,
            });
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L312-323)
```rust
        for vault in BORROW.range(deps.storage, None, None, Order::Ascending) {
            let debt = Debt::from(vault?.1.delegate(deps.querier, contract, &self.account)?);
            let value = debt.value_usd(deps.querier)?;
            if value.is_zero() {
                continue;
            }
            ca.debts.push(Valued {
                item: debt,
                value,
                value_adjusted: value,
            });
        }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L340-356)
```rust
impl From<CreditAccount> for AccountResponse {
    fn from(value: CreditAccount) -> Self {
        Self {
            ltv: value.adjusted_ltv(),
            tag: value.tag,
            owner: value.owner,
            account: value.account.contract(),
            collaterals: value
                .collaterals
                .iter()
                .map(CollateralResponse::from)
                .collect(),
            debts: value.debts.iter().map(DebtResponse::from).collect(),
            liquidation_preferences: value.liquidation_preferences,
        }
    }
}
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-76)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L163-169)
```rust
            Ok(response.add_message(ExecuteMsg::CheckAccount { addr }.call(&ca)?))
        }
        ExecuteMsg::CheckAccount { addr } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_safe(&config.adjustment_threshold)?;
            Ok(Response::default())
```
