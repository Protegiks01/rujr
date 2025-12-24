# Audit Report

## Title
Config Staleness Vulnerability: Accounts Recalculate LTV with Current Collateral Ratios Causing Unfair Liquidations

## Summary
The `load()` function recalculates account collateral adjusted values using the current config's `collateral_ratios` instead of storing them at account creation time. This causes all existing accounts to immediately reflect new collateral ratio values, making previously safe accounts instantly liquidatable when ratios decrease, violating the protocol's LTV determinism invariant.

## Finding Description

The vulnerability exists in how account state is stored and loaded. When an account is created, only basic metadata is persisted [1](#0-0) , notably excluding collateral `value_adjusted` amounts and LTV calculations.

Every time an account is loaded, the `to_credit_account()` function recalculates these critical values using the **current** config's `collateral_ratios` [2](#0-1) , specifically at [3](#0-2) .

The `value_adjusted()` calculation multiplies USD value by the current ratio [4](#0-3) , with the critical line being [5](#0-4)  which uses `unwrap_or_default()` returning zero if the ratio is removed.

The admin can modify collateral ratios via sudo [6](#0-5)  at any time without notifying users or providing migration periods.

This breaks the **Post-Adjustment LTV Check** invariant: accounts that passed safety checks at creation can suddenly fail them through no user action, only config changes.

**Attack Scenario:**
1. User creates account with BTC collateral ($10,000 USD, ratio=0.8 → adjusted=$8,000)
2. User borrows $6,000 → LTV = 75% (safe, adjustment_threshold=95%)
3. Admin reduces BTC ratio to 0.6 for risk management
4. Account now has adjusted=$6,000 → LTV = 100% → immediately liquidatable
5. User loses collateral through liquidation despite doing nothing wrong

This affects all critical operations that load accounts [7](#0-6) , [8](#0-7) , [9](#0-8) , [10](#0-9) .

## Impact Explanation

**HIGH Severity** - This vulnerability causes:

1. **Loss of User Funds**: Users can be liquidated unfairly, losing collateral when ratio decreases
2. **Systemic Undercollateralization Risk**: If ratios increase, liquidatable accounts escape liquidation, threatening protocol solvency
3. **No User Protection**: Users cannot prevent or react to sudden LTV changes caused by config updates
4. **State Inconsistency**: Same account can have different LTV values across different queries/operations if config changes mid-execution

The adjusted LTV calculation [11](#0-10)  divides debt by collateral_adjusted, making it directly dependent on ratio changes.

## Likelihood Explanation

**HIGH Likelihood** - This will occur whenever:
- Admin adjusts collateral ratios for legitimate risk management
- New assets require ratio updates
- Market conditions necessitate ratio changes
- Governance implements protocol improvements

Even benevolent admin actions trigger this vulnerability. No malicious intent required - it's an inherent code design flaw affecting all accounts globally and instantaneously upon any ratio modification.

## Recommendation

Store collateral ratios with each account at creation time to ensure LTV calculations remain deterministic:

```rust
#[cw_serde]
struct Stored {
    owner: Addr,
    account: Addr,
    tag: String,
    liquidation_preferences: LiquidationPreferences,
    // Add this field:
    collateral_ratios_snapshot: BTreeMap<String, Decimal>,
}
```

Modify `to_credit_account()` to use the stored snapshot instead of current config. For existing accounts, implement a migration mechanism with grace periods allowing users to adjust positions before new ratios apply.

Alternatively, only apply ratio changes to new borrows/deposits, grandfathering existing positions.

## Proof of Concept

```rust
#[test]
fn test_config_staleness_causes_unfair_liquidation() {
    use cosmwasm_std::{coin, Decimal};
    use std::str::FromStr;
    
    let mut app = mock_rujira_app();
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::from_str("1.0").unwrap()),
            ("BTC", Decimal::from_str("50000.0").unwrap()),
        ]);
    });

    let owner = app.api().addr_make("user");
    let fees = app.api().addr_make("fees");
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    
    // Set initial BTC ratio to 0.8
    credit.set_collateral(&mut app, "btc-btc", "0.8");
    
    // Create account and deposit 1 BTC ($50,000 * 0.8 = $40,000 adjusted)
    let account = credit.create_account(&mut app, &owner, "", "", Binary::new(vec![0]));
    app.send_tokens(owner.clone(), account.account.clone(), &[coin(100000000, "btc-btc")]).unwrap();
    
    // Setup vault and borrow $30,000 USDC (LTV = 75%, safe)
    let vault = GhostVault::create(&mut app, &owner, "USDC");
    vault.set_borrower(&mut app, credit.addr().as_str(), Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    vault.deposit(&mut app, &owner, 50000000000, "USDC").unwrap();
    
    credit.account_borrow(&mut app, &account, 30000000000, "USDC").unwrap();
    
    // Verify account is safe (LTV < 95%)
    let acc = credit.query_account(&app, &account.account);
    assert!(acc.ltv < Decimal::from_str("0.95").unwrap());
    
    // Admin reduces BTC ratio to 0.6 for risk management
    credit.set_collateral(&mut app, "btc-btc", "0.6");
    
    // Account now has adjusted = $30,000, debt = $30,000, LTV = 100%
    let acc_after = credit.query_account(&app, &account.account);
    assert!(acc_after.ltv >= Decimal::one()); // Now liquidatable!
    
    // User can be liquidated despite doing nothing wrong
    // This proves accounts are vulnerable to config changes
}
```

**Notes:**
- This vulnerability affects all accounts simultaneously when config changes
- The issue stems from runtime recalculation rather than storing state at creation
- Users have no way to protect themselves or receive warnings before ratio changes
- Even legitimate admin actions (adjusting risk parameters) cause user harm
- The `load()` function signature accepting config as parameter [12](#0-11)  enables but doesn't require this behavior - the design choice to not persist ratios is the root cause

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L21-28)
```rust
#[cw_serde]
struct Stored {
    owner: Addr,
    account: Addr,
    #[serde(default)]
    tag: String,
    liquidation_preferences: LiquidationPreferences,
}
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L141-150)
```rust
    pub fn load(
        deps: Deps,
        config: &Config,
        contract: &Addr,
        account: Addr,
    ) -> Result<Self, ContractError> {
        Self::store()
            .load(deps.storage, account)?
            .to_credit_account(deps, contract, config)
    }
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

**File:** contracts/rujira-ghost-credit/src/account.rs (L285-326)
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
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/collateral.rs (L16-29)
```rust
    pub fn value_adjusted(
        &self,
        deps: Deps,
        ratios: &BTreeMap<String, Decimal>,
    ) -> Result<Decimal, CollateralError> {
        self.balance()
            .into_vec()
            .iter()
            .try_fold(Decimal::zero(), |agg, v| {
                Ok(v.value_usd(deps.querier)?
                    .mul(ratios.get(&v.denom).copied().unwrap_or_default())
                    .add(agg))
            })
    }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L75-75)
```rust
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L107-107)
```rust
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L153-153)
```rust
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L167-167)
```rust
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L369-379)
```rust
        SudoMsg::SetCollateral {
            denom,
            collateralization_ratio,
        } => {
            config
                .collateral_ratios
                .insert(denom, collateralization_ratio);
            config.validate()?;
            config.save(deps.storage)?;
            Ok(Response::default())
        }
```
