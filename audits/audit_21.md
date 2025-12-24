# Audit Report

## Title
Immediate Collateral Ratio Changes Enable Mass Liquidations of Healthy Positions Without Safeguards

## Summary
The protocol allows instantaneous changes to collateral ratios through `SudoMsg::SetCollateral` without any timelock, gradual adjustment mechanism, or impact assessment. When collateral ratios are decreased, all existing positions immediately have their adjusted collateral values recalculated using the new ratios, causing their LTV to spike. This can instantly convert healthy positions into liquidatable ones, resulting in mass liquidations and widespread user losses.

## Finding Description
The vulnerability exists across multiple contract components and breaks critical protocol invariants:

**1. Unprotected Collateral Ratio Updates:** [1](#0-0) 

The `SetCollateral` sudo message allows immediate modification of collateralization ratios with only basic validation (ratio <= 1.0). There is no timelock, no gradual adjustment period, and no check to prevent existing healthy positions from becoming liquidatable.

**2. Immediate LTV Impact:** [2](#0-1) 

When accounts are loaded via `to_credit_account()`, the adjusted collateral value is recalculated using the current config's collateral ratios. This means ratio changes take effect immediately upon any account query or operation.

**3. Value Adjustment Calculation:** [3](#0-2) 

The `value_adjusted()` function multiplies the USD value by the collateral ratio. When the ratio decreases, the adjusted value decreases proportionally.

**4. LTV Calculation:** [4](#0-3) 

The `adjusted_ltv()` calculates LTV as `total_debt / total_adjusted_collateral`. When adjusted collateral decreases due to ratio changes, LTV increases proportionally.

**5. Liquidation Trigger:** [5](#0-4) 

Accounts with `adjusted_ltv >= liquidation_threshold` can be immediately liquidated.

**Exploitation Scenario:**

1. User deposits 10,000 USD worth of BTC as collateral (collateral_ratio = 0.9)
2. User borrows 6,000 USD worth of stablecoins
3. Account LTV = 6,000 / 9,000 = 66.67% (healthy, below 100% liquidation threshold)
4. Governance reduces BTC collateral_ratio from 0.9 to 0.5 (44% reduction in haircut)
5. User's adjusted collateral instantly becomes 10,000 × 0.5 = 5,000 USD
6. Account LTV instantly jumps to 6,000 / 5,000 = 120% (now liquidatable)
7. Liquidators immediately liquidate the position
8. User loses collateral due to a parameter change, not market price movement

**Invariant Violations:**

- **Post-Adjustment LTV Check Invariant**: The protocol enforces that user operations must maintain LTV < adjustment_threshold, but governance can bypass this by changing ratios externally
- **Safe Liquidation Outcomes Invariant**: Positions become liquidatable without market price changes or user actions, violating user expectations
- **Protocol Solvency**: Mass liquidations due to sudden parameter changes can create market panic and cascading liquidations

## Impact Explanation
**Severity: High**

**Direct User Losses:**
- Users with healthy positions can lose their collateral through liquidation without any market price movement
- Liquidation fees (1% protocol + 0.5% liquidator per default config) are extracted from user collateral
- Users may be unable to react in time to save their positions

**Systemic Risk:**
- If a widely-held collateral type has its ratio reduced, hundreds or thousands of accounts could become liquidatable simultaneously
- Mass liquidation events can cause market panic and further price crashes
- Protocol reputation damage and loss of user confidence

**Example Loss Calculation:**
- User with 10,000 USD BTC collateral and 6,000 USD debt
- Ratio change from 0.9 to 0.5
- Position liquidated, extracting ~1.5% in fees = 150 USD direct loss
- Potential additional slippage losses up to 30% (liquidation_max_slip) = additional 3,000 USD loss
- Total potential user loss: 3,150 USD or 31.5% of collateral value

## Likelihood Explanation
**Likelihood: Medium-High**

**Preconditions:**
- Governance decides to reduce collateral ratios (could happen during market stress, risk assessment updates, or governance compromise)
- Active positions exist with the affected collateral type
- No alternative safeguards are implemented

**Realistic Scenarios:**
1. **Risk Management Response**: During market volatility, governance may reduce collateral ratios to protect protocol solvency, inadvertently triggering mass liquidations
2. **Governance Error**: Accidental misconfiguration (e.g., setting ratio to 0.5 instead of 0.95)
3. **Proactive De-risking**: Governance identifies a risky asset and reduces its ratio, causing immediate user impact
4. **Governance Compromise**: Although trusted roles are generally assumed secure, lack of safeguards means any compromise has immediate catastrophic impact

**Comparison with Industry Standards:**
Major DeFi lending protocols (Compound, Aave, MakerDAO) all implement timelocks (24-48 hours) for parameter changes, allowing users to adjust positions before changes take effect. The absence of such protections in Rujira significantly increases likelihood of harmful outcomes.

## Recommendation

Implement a multi-layered protection system:

**1. Add Timelock Mechanism:**
```rust
pub struct PendingCollateralRatioChange {
    pub denom: String,
    pub new_ratio: Decimal,
    pub effective_block: u64,
}

// Minimum delay of 24-48 hours in blocks
const COLLATERAL_RATIO_CHANGE_DELAY_BLOCKS: u64 = 17280; // ~48 hours at 10s/block
```

**2. Implement Staged Updates:**
Store pending changes and only apply them after the timelock expires:
```rust
SudoMsg::ProposeCollateralRatio { denom, ratio } => {
    // Validate and store pending change
    PENDING_RATIO_CHANGES.save(deps.storage, denom, &PendingCollateralRatioChange {
        denom: denom.clone(),
        new_ratio: ratio,
        effective_block: env.block.height + COLLATERAL_RATIO_CHANGE_DELAY_BLOCKS,
    })?;
}

SudoMsg::ApplyCollateralRatio { denom } => {
    let pending = PENDING_RATIO_CHANGES.load(deps.storage, denom)?;
    ensure!(env.block.height >= pending.effective_block, ContractError::TimelockNotExpired);
    config.collateral_ratios.insert(denom, pending.new_ratio);
    config.save(deps.storage)?;
    PENDING_RATIO_CHANGES.remove(deps.storage, denom);
}
```

**3. Add Gradual Adjustment:**
Implement progressive ratio changes over multiple blocks to give users time to adjust:
```rust
// Limit maximum single adjustment to 10% of current value
const MAX_RATIO_CHANGE_PERCENT: Decimal = Decimal::percent(10);
```

**4. Add Emergency Circuit Breaker:**
Monitor liquidation volume and pause new liquidations if mass liquidation event is detected:
```rust
pub struct LiquidationRateLimit {
    pub liquidations_last_hour: u32,
    pub max_liquidations_per_hour: u32,
}
```

## Proof of Concept

Add this test to `contracts/rujira-ghost-credit/src/tests/contract.rs`:

```rust
#[test]
fn test_collateral_ratio_decrease_causes_immediate_liquidation() {
    use std::str::FromStr;
    use cosmwasm_std::{coin, coins, Decimal};
    use cw_multi_test::Executor;
    use rujira_rs::ghost::credit::AccountMsg;
    
    let mut app = mock_rujira_app();
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::from_str("1.0").unwrap()),
            ("BTC", Decimal::from_str("50000.0").unwrap()), // BTC at $50k
        ]);
    });

    let owner = app.api().addr_make("owner");
    let user = app.api().addr_make("user");
    let liquidator = app.api().addr_make("liquidator");
    let fees = app.api().addr_make("fee");
    
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    
    // Set initial collateral ratio to 0.9 (90% haircut)
    credit.set_collateral(&mut app, BTC, "0.9");
    credit.set_collateral(&mut app, USDC, "0.9");
    
    // Create vault and configure
    let vault = GhostVault::create(&mut app, &owner, USDC);
    vault.set_borrower(&mut app, credit.addr().as_str(), Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    vault.deposit(&mut app, &owner, 1000000, USDC).unwrap();
    
    // User creates account and deposits 1 BTC ($50,000 worth)
    let account = credit.create_account(&mut app, &user, "", "", Binary::new(vec![1]));
    
    // Fund user account with collateral
    app.init_modules(|router, _api, storage| {
        router.bank.init_balance(storage, &user, vec![coin(100000000, BTC)])
    }).unwrap();
    app.send_tokens(user.clone(), account.account.clone(), &coins(100000000, BTC)).unwrap();
    
    // User borrows $30,000 USDC (60% LTV based on adjusted collateral)
    // Adjusted collateral = $50,000 * 0.9 = $45,000
    // LTV = $30,000 / $45,000 = 66.67% (safe, below liquidation threshold of 100%)
    credit.account_borrow(&mut app, &account, 30000000000, USDC).unwrap();
    
    // Verify position is healthy
    let account_state = credit.query_account(&app, &account.account);
    assert!(account_state.ltv < Decimal::one()); // LTV should be ~0.67
    
    // VULNERABILITY: Governance reduces BTC collateral ratio from 0.9 to 0.5
    credit.set_collateral(&mut app, BTC, "0.5");
    
    // Position is now immediately liquidatable
    // New adjusted collateral = $50,000 * 0.5 = $25,000
    // New LTV = $30,000 / $25,000 = 120% (LIQUIDATABLE!)
    let account_state_after = credit.query_account(&app, &account.account);
    assert!(account_state_after.ltv >= Decimal::one()); // LTV should be ~1.2
    
    // Liquidator can now liquidate the previously healthy position
    let liquidation_result = credit.liquidate(
        &mut app, 
        &account_state_after,
        vec![LiquidateMsg::Repay(USDC.to_string())]
    );
    
    // Liquidation succeeds, user loses collateral due to parameter change, not price movement
    assert!(liquidation_result.is_ok());
    
    println!("VULNERABILITY CONFIRMED:");
    println!("- Initial LTV: {}", account_state.ltv);
    println!("- LTV after ratio change: {}", account_state_after.ltv);
    println!("- Position became liquidatable without any price change");
    println!("- User lost collateral due to governance parameter change");
}
```

**Notes**

This vulnerability represents a critical governance risk in the protocol design. While the trust model assumes governance acts in good faith, the complete absence of safeguards means that:

1. **Accidental Harm**: Even well-intentioned governance can accidentally harm users through misconfiguration or poor timing
2. **No User Protection**: Users have no warning or time to adjust their positions before parameter changes take effect
3. **Violates DeFi Standards**: Industry-standard lending protocols implement timelocks specifically to prevent this scenario
4. **Cascading Risk**: Mass liquidations can trigger market panic and further price drops, creating systemic risk

The fix requires implementing at minimum a 24-48 hour timelock on collateral ratio changes, with clear communication channels to warn users of pending changes. Additional protections like gradual adjustments and liquidation rate limits would further reduce risk.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-76)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
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

**File:** contracts/rujira-ghost-credit/src/account.rs (L285-310)
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
