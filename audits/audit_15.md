# Audit Report

## Title
Liquidators Can Bypass Slippage Limits When Oracle Reports Zero Value for Collateral, Enabling Excessive Collateral Extraction

## Summary
When the THORChain oracle reports zero value for collateral assets due to oracle failures or manipulation, liquidators can sell this collateral without any slippage protection. The `validate_liquidation()` function's slippage calculation performs division by zero when `spent_usd` is zero, returning zero via `unwrap_or_default()`, which bypasses the critical `liquidation_max_slip` check designed to protect account owners from excessive collateral loss.

## Finding Description

The vulnerability exists in the interaction between two functions:

1. **Account Loading Filter** - When a `CreditAccount` is loaded, collateral with zero USD value is filtered out: [1](#0-0) 

2. **Slippage Calculation** - The `validate_liquidation()` function calculates slippage based on the filtered collateral list: [2](#0-1) 

**The Attack Path:**

When an account has collateral that the oracle values at zero (but has real market value), the following occurs:

1. The zero-valued collateral is filtered out when loading `CreditAccount` (lines 302-304), so it doesn't appear in the `collaterals` vector
2. The physical coins still exist in the account contract and can be swapped via `LiquidateMsg::Execute`
3. During liquidation validation, `balance()` only includes collateral from the `collaterals` vector: [3](#0-2) 

4. When calculating `spent = old.balance().sent(&balance)`, the zero-valued collateral is not included (line 255)
5. `spent_usd = 0`, causing `checked_div(spent_usd)` to return `None`, which becomes zero via `unwrap_or_default()` (line 269)
6. The slippage check at lines 273-278 is skipped because `!slippage.is_zero()` evaluates to false
7. The liquidator profits from selling real-value collateral without slippage limits

**Broken Invariant:**

This breaks **Invariant #3**: "Safe Liquidation Outcomes: Liquidations only trigger when adjusted_ltv >= liquidation_threshold and must stop before over-selling collateral, respecting user preferences and max slip limits."

The `liquidation_max_slip` parameter (validated to be < 100% in config) is meant to limit how much collateral value can be extracted beyond debt repaid: [4](#0-3) 

## Impact Explanation

**High Severity** - This vulnerability enables direct loss of user collateral beyond protocol-defined limits:

- **Financial Loss**: Account owners lose collateral that should be protected by the `liquidation_max_slip` parameter (e.g., if slip limit is 5%, but 100% of zero-valued collateral is sold)
- **Economic Exploitation**: Liquidators can extract maximum value from accounts with oracle-failed collateral, profiting at the expense of users
- **Trust Violation**: The protocol's slippage protection mechanism, a core safety feature, is completely bypassed

**Example Scenario:**
- Account has 10 ETH (oracle reports $0 due to failure, real market value $30,000) + 1 BTC ($50,000)
- Debt: $40,000
- `liquidation_max_slip` = 5% (should limit extraction to ~$42,000 to repay $40,000 debt)
- Liquidator swaps all 10 ETH for $30,000 worth of debt tokens and repays
- Slippage check is bypassed (spent_usd = 0)
- Total extracted: $30,000 instead of the ~$2,000 that slippage limits should allow
- User loses $28,000 more collateral than intended

## Likelihood Explanation

**Medium-to-High Likelihood:**

- **Trigger Condition**: Requires oracle to report zero value for collateral
  - Oracle failures/downtime (medium likelihood)
  - New asset listings before oracle integration (high likelihood)
  - Oracle manipulation attacks (low-to-medium likelihood)
  
- **Exploitability**: Once condition exists, exploitation is straightforward - any liquidator monitoring for such accounts can execute the attack with standard liquidation messages

- **Detection**: Liquidators actively monitor for profitable liquidation opportunities, making discovery of exploitable accounts likely

- **Frequency**: While not constant, oracle issues are recurring events in DeFi protocols, making this a realistic attack vector

## Recommendation

Add a check to prevent liquidation of collateral that has zero oracle value, or ensure zero-valued collateral is still tracked in slippage calculations:

**Option 1 - Prevent Zero-Value Collateral Liquidation:**

```rust
pub fn validate_liquidation(
    &self,
    deps: Deps,
    config: &Config,
    old: &Self,
) -> Result<(), ContractError> {
    let balance = self.balance();
    let spent = old.balance().sent(&balance);

    for coin in spent.clone().into_vec() {
        self.liquidation_preferences
            .order
            .validate(&coin, &balance)?;
    }

    let spent_usd = spent.value_usd(deps.querier)?;
    
    // NEW: Prevent liquidation if spent collateral has zero value
    // This protects against oracle failures
    if !spent.into_vec().is_empty() && spent_usd.is_zero() {
        return Err(ContractError::ZeroValueCollateralLiquidation {});
    }
    
    let repaid = old.debt().sent(&self.debt());
    let repaid_usd = repaid.value_usd(deps.querier)?;
    let slippage = spent_usd
        .checked_sub(repaid_usd)
        .unwrap_or_default()
        .checked_div(spent_usd)
        .unwrap_or_default();

    if !slippage.is_zero() {
        ensure!(
            slippage.le(&config.liquidation_max_slip),
            ContractError::LiquidationMaxSlipExceeded { slip: slippage }
        );
    }

    Ok(())
}
```

**Option 2 - Track All Physical Balances:**

Modify `to_credit_account` to query and track physical balances separately, so spent calculations include all coins regardless of oracle value. Then enforce slippage checks even when oracle reports zero by using physical coin amounts as a fallback.

## Proof of Concept

While test files are out of scope, here's the exploitation sequence that would occur:

```rust
// Setup: Account with zero-valued collateral due to oracle failure
// 1. Account has: 10 ETH (physical), 1 BTC ($50k value)
// 2. Oracle reports: ETH = $0, BTC = $50k
// 3. Debt: $40k
// 4. liquidation_max_slip = 5% (should limit to ~$42k extraction)

// Step 1: CreditAccount is loaded
// - to_credit_account filters out ETH (line 302-304)
// - account.collaterals = [BTC only]
// - adjusted_ltv = $40k / $50k = 0.8 (80%, at liquidation threshold)

// Step 2: Liquidator calls ExecuteMsg::Liquidate with:
// - LiquidateMsg::Execute { swap 10 ETH for USDC on DEX }
// - LiquidateMsg::Repay { USDC }

// Step 3: In DoLiquidate, validate_liquidation is called:
let original_account = // Loaded before swap, collaterals = [BTC]
let current_account = // Loaded after swap, collaterals = [BTC] (ETH still $0)

// Line 254-255: balance calculations
let balance = current_account.balance(); // Only BTC
let spent = original_account.balance().sent(&balance); // Empty (no change)

// Line 263: spent_usd = 0 (no BTC was spent)
// Line 266-270: slippage = (0 - repaid_usd) / 0
//               checked_div(0) returns None
//               unwrap_or_default() = Decimal::zero()

// Line 273: if !Decimal::zero().is_zero() → FALSE
// Slippage check is SKIPPED

// Result: 10 ETH (real value ~$30k) sold, only limited by LTV checks
// Normal slippage would have limited to $42k total extraction for $40k debt
// User loses ~$28k more than slippage limits intended
```

**Key Files Referenced:**
- Account loading and filtering: [5](#0-4) 
- Liquidation validation flow: [6](#0-5) 
- Balance calculation: [7](#0-6) 

## Notes

This vulnerability demonstrates a critical mismatch between physical asset holdings and oracle-reported values. The protocol correctly filters zero-valued assets from LTV calculations to prevent division-by-zero errors, but fails to account for the fact that these assets can still be physically swapped during liquidation. The slippage protection mechanism assumes all collateral movements will be captured in the `spent` calculation, but this assumption breaks when collateral is filtered from the `CreditAccount` representation while still existing in the underlying account contract.

The issue requires oracle failures or manipulation to trigger but is highly exploitable once present, warranting High severity classification.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L235-239)
```rust
    fn balance(&self) -> NativeBalance {
        self.collaterals
            .iter()
            .fold(NativeBalance::default(), |agg, v| v.item.balance().add(agg))
    }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L248-281)
```rust
    pub fn validate_liquidation(
        &self,
        deps: Deps,
        config: &Config,
        old: &Self,
    ) -> Result<(), ContractError> {
        let balance = self.balance();
        let spent = old.balance().sent(&balance);

        for coin in spent.clone().into_vec() {
            self.liquidation_preferences
                .order
                .validate(&coin, &balance)?;
        }

        let spent_usd = spent.value_usd(deps.querier)?;
        let repaid = old.debt().sent(&self.debt());
        let repaid_usd = repaid.value_usd(deps.querier)?;
        let slippage = spent_usd
            .checked_sub(repaid_usd)
            .unwrap_or_default()
            .checked_div(spent_usd)
            .unwrap_or_default();

        // Check against config liquidation slip
        if !slippage.is_zero() {
            ensure!(
                slippage.le(&config.liquidation_max_slip),
                ContractError::LiquidationMaxSlipExceeded { slip: slippage }
            );
        }

        Ok(())
    }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L285-327)
```rust
    fn to_credit_account(
        &self,
        deps: Deps,
        contract: &Addr,
        config: &Config,
    ) -> Result<CreditAccount, ContractError> {
        let mut ca = CreditAccount {
            owner: self.owner.clone(),
            tag: self.tag.clone(),
            account: Account::load(deps, &self.account)?,
            collaterals: vec![],
            debts: vec![],
            liquidation_preferences: self.liquidation_preferences.clone(),
        };

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
        }

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

        Ok(ca)
    }
}
```

**File:** contracts/rujira-ghost-credit/src/config.rs (L20-20)
```rust
    pub liquidation_max_slip: Decimal,
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-148)
```rust
        ExecuteMsg::DoLiquidate {
            addr,
            mut queue,
            payload,
        } => {
            ensure_eq!(info.sender, ca, ContractError::Unauthorized {});
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            let original_account: CreditAccount = from_json(&payload)?;

            let check = account
                // Check safe against the liquidation threshold
                .check_safe(&config.liquidation_threshold)
                // Check we've not gone below the adjustment threshold
                .and_then(|_| account.check_unsafe(&config.adjustment_threshold))
                .and_then(|_| {
                    account.validate_liquidation(deps.as_ref(), &config, &original_account)
                });
            match (queue.pop(), check) {
                (_, Ok(())) => Ok(Response::default()),
                (None, Err(err)) => {
                    // We're done and the Account hasn't passed checks. Fail
                    Err(err)
                }
                (Some((msg, is_preference)), Err(_)) => {
                    // Not safe, more messages to go. Continue
                    Ok(execute_liquidate(
                        deps.as_ref(),
                        env.clone(),
                        info,
                        &config,
                        msg,
                        &account,
                        if is_preference {
                            REPLY_ID_PREFERENCE
                        } else {
                            REPLY_ID_LIQUIDATOR
                        },
                    )?
                    .add_message(
                        ExecuteMsg::DoLiquidate {
                            addr: account.id().to_string(),
                            queue,
                            payload,
                        }
                        .call(&ca)?,
                    ))
                }
            }
```

**File:** packages/rujira-rs/src/native_balance_plus.rs (L11-19)
```rust
    fn sent(&self, new: &Self) -> Self {
        let mut spent = self.clone();
        for coin in new.clone().into_vec() {
            // Swallow the error with a NOOP if we have received a new token,
            // which will try and subtract the new from the original balance where it doesn't exist
            spent = spent.clone().sub_saturating(coin).unwrap_or(spent.clone())
        }
        spent
    }
```
