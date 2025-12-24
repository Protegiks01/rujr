# Audit Report

## Title
Collateral Ratio Updates Cause Immediate Undercollateralization of Existing Accounts Without Grace Period

## Summary
The protocol dynamically loads `collateral_ratios` from the current config for all LTV calculations, but does not re-validate existing accounts after ratio updates. This allows both front-running attacks when ratios are decreased and immediate unfair liquidations of previously healthy accounts.

## Finding Description

The Rujira Protocol's credit account system calculates adjusted LTV by loading collateral ratios from the current global config on every account operation. When governance updates `collateral_ratios` via `SudoMsg::SetCollateral`, the change takes effect immediately for all accounts without any validation of existing positions or grace period. [1](#0-0) 

When an account is loaded, it dynamically recalculates its collateral values using the **current** `config.collateral_ratios`: [2](#0-1) 

The `value_adjusted` calculation multiplies the USD value by the current collateral ratio: [3](#0-2) 

And the `adjusted_ltv` is calculated as debt divided by adjusted collateral: [4](#0-3) 

**Attack Scenario:**

1. **Initial State**: ATOM has collateral_ratio = 0.9 (90%), adjustment_threshold = 0.95, liquidation_threshold = 1.0
2. **Governance Action**: Admin broadcasts `SudoMsg::SetCollateral` to reduce ATOM ratio to 0.6 due to increased volatility
3. **Front-Running Attack**: 
   - Attacker observes governance transaction in mempool
   - Attacker submits transaction to create account, deposit $1000 ATOM, borrow $850
   - With ratio 0.9: adjusted_collateral = $900, LTV = 850/900 = 94.4% < 95% ✓
   - `CheckAccount` passes
4. **Governance Transaction Executes**: Ratio changes to 0.6
5. **Result**: 
   - Account now has: adjusted_collateral = $600, debt = $850
   - LTV = 850/600 = 141.67% >> 100% liquidation_threshold
   - Account is immediately liquidatable with massive losses

This breaks **Invariant #2** (Post-Adjustment LTV Check) because accounts can exceed the adjustment threshold without any owner operation, purely due to external config changes. It also violates the protocol's safety guarantees that users maintaining LTV below adjustment_threshold are safe from liquidation.

## Impact Explanation

**High Severity** due to multiple critical impacts:

1. **Unfair Liquidations**: Honest users who maintained safe positions (LTV < adjustment_threshold) can be instantly liquidated when collateral ratios decrease, with no opportunity to add collateral or repay debt
2. **Protocol Insolvency Risk**: Front-runners can intentionally create maximally-leveraged positions seconds before ratio decreases, then abandon accounts if liquidation isn't profitable, leaving protocol with bad debt
3. **Systemic Undercollateralization**: A single governance action to reduce ratios can render dozens of accounts undercollateralized simultaneously, overwhelming liquidators and causing cascading failures
4. **Economic Loss**: Users lose liquidation penalties (1-5%) plus liquidator fees plus slippage on collateral sales, all because of a timing issue beyond their control

Using realistic protocol parameters (adjustment_threshold = 95%, liquidation_threshold = 100%), a ratio decrease from 0.9 to 0.6 (33% reduction) turns a 94% LTV account into a 141% LTV account instantly.

## Likelihood Explanation

**High Likelihood** because:

1. **Frequent Occurrence**: Collateral ratios must be adjusted regularly as market conditions change, making this a recurring risk
2. **Low Attack Complexity**: Any user monitoring the mempool can execute this attack with standard front-running techniques
3. **No Protection Mechanisms**: The protocol has zero defenses against this:
   - No grace period for existing accounts
   - No validation of existing accounts after ratio changes  
   - No snapshot of ratios per account
4. **Economic Incentive**: Attackers can profit by borrowing maximally under old ratios then either getting liquidated at favorable terms or if price moves favorably, repaying and keeping the borrowed funds

Even without malicious front-running, honest users are harmed whenever ratios decrease, as they have no advance warning or time to adjust positions.

## Recommendation

Implement one or more of these protective mechanisms:

**Option 1: Grace Period with Gradual Ratio Updates**
```rust
pub struct CollateralRatioSchedule {
    pub current: Decimal,
    pub target: Decimal,
    pub deadline: u64, // block height
}

// In SudoMsg::SetCollateral
impl Config {
    pub fn schedule_ratio_change(
        &mut self,
        denom: String,
        new_ratio: Decimal,
        grace_blocks: u64,
        current_block: u64,
    ) {
        self.ratio_schedules.insert(denom, CollateralRatioSchedule {
            current: self.collateral_ratios[&denom],
            target: new_ratio,
            deadline: current_block + grace_blocks,
        });
    }
}
```

**Option 2: Per-Account Ratio Snapshots**
Store the collateral ratio in the account at creation/borrow time, only updating it when the user performs an action:

```rust
pub struct Stored {
    owner: Addr,
    account: Addr,
    tag: String,
    collateral_ratio_snapshot: BTreeMap<String, Decimal>, // NEW
    liquidation_preferences: LiquidationPreferences,
}
```

**Option 3: Minimum Validation After Config Changes**
Add a post-update validation that prevents ratio decreases if any account would become liquidatable:

```rust
// In SudoMsg::SetCollateral
if new_ratio < current_ratio {
    // Query all accounts and ensure none become liquidatable
    ensure_no_immediate_liquidations(deps, &denom, new_ratio)?;
}
```

**Recommended Approach**: Combine Options 1 and 3 - implement a grace period AND validate that no accounts exceed liquidation_threshold immediately after the change.

## Proof of Concept

```rust
#[test]
fn test_collateral_ratio_frontrun_attack() {
    use std::str::FromStr;
    use cosmwasm_std::{coin, Decimal};
    use rujira_rs_testing::mock_rujira_app;
    use crate::mock::GhostCredit;
    use crate::tests::support::USDC;
    use rujira_ghost_vault::mock::GhostVault;

    let mut app = mock_rujira_app();
    
    // Setup oracle prices
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::from_str("1.0").unwrap()),
        ]);
    });

    let owner = app.api().addr_make("owner");
    let attacker = app.api().addr_make("attacker");
    let fees = app.api().addr_make("fee");
    
    // Deploy contracts with adjustment_threshold=0.95, liquidation_threshold=1.0
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    
    // Initial collateral ratio = 0.9 (90%)
    credit.set_collateral(&mut app, USDC, "0.9");
    
    // Setup vault
    let vault = GhostVault::create(&mut app, &owner, USDC);
    vault.set_borrower(&mut app, credit.addr().as_str(), cosmwasm_std::Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    vault.deposit(&mut app, &owner, 10000, USDC).unwrap();
    
    // Fund attacker with $1000 USDC
    app.init_modules(|router, _api, storage| {
        router.bank.init_balance(storage, &attacker, vec![coin(1000, USDC)])
    }).unwrap();
    
    // Attacker front-runs the ratio decrease
    // Step 1: Create account
    let res = credit.create_account(&mut app, &attacker, "", "", cosmwasm_std::Binary::new(vec![0]));
    let account = credit.query_accounts(&app, &attacker, None).accounts[0].clone();
    
    // Step 2: Deposit collateral
    app.send_tokens(attacker.clone(), account.account.clone(), &vec![coin(1000, USDC)]).unwrap();
    
    // Step 3: Borrow maximum under old ratio (LTV = 94.4% < 95%)
    // adjusted_collateral = 1000 * 0.9 = 900
    // max_borrow = 900 * 0.944 = 849.6, round to 850
    credit.account_borrow(&mut app, &account, 850, USDC).unwrap();
    
    // Verify account is safe under old ratio
    let account_state = credit.query_account(&app, &account.account);
    assert!(account_state.ltv < Decimal::from_str("0.95").unwrap(), 
            "Account should be below adjustment threshold");
    
    // Governance transaction executes: reduce ratio to 0.6
    credit.set_collateral(&mut app, USDC, "0.6");
    
    // Query account again - now undercollateralized!
    let account_state = credit.query_account(&app, &account.account);
    // adjusted_collateral = 1000 * 0.6 = 600
    // LTV = 850 / 600 = 1.4167 (141.67%)
    assert!(account_state.ltv > Decimal::one(), 
            "Account should now exceed liquidation threshold");
    
    // Account is now liquidatable despite user following all rules
    // This demonstrates the vulnerability
}
```

This test demonstrates that a user who maintained a safe LTV (94.4% < 95% adjustment_threshold) becomes immediately liquidatable (141.67% > 100% liquidation_threshold) when governance reduces the collateral ratio, with no grace period or opportunity to adjust their position.

### Citations

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
