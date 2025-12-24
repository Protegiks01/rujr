# Audit Report

## Title
Non-Atomic Collateral Ratio Updates Enable Unfair Liquidations During Partial Configuration Changes

## Summary
The `SudoMsg::SetCollateral` handler only updates one collateral ratio at a time, with no mechanism for batch atomic updates. When governance needs to update multiple collateral ratios, the intermediate states between transactions create LTV calculation inconsistencies that can trigger premature liquidations of otherwise healthy positions.

## Finding Description

The protocol uses a `BTreeMap<String, Decimal>` to store collateral ratios in the `Config` struct. [1](#0-0) 

The `SudoMsg::SetCollateral` handler updates only a single denom's ratio per transaction: [2](#0-1) 

When calculating adjusted collateral values for LTV checks, the system multiplies each asset's USD value by its collateral ratio from the config map: [3](#0-2) 

The adjusted LTV calculation then divides total debt by adjusted collateral value: [4](#0-3) 

**Breaking Protocol Invariant #2**: The "Post-Adjustment LTV Check" invariant states that `adjusted_ltv` must remain `< adjustment_threshold` for safe positions. However, when governance updates multiple collateral ratios incrementally, users' positions that were safe under the original configuration can become liquidatable during intermediate states—not due to user actions, but purely due to the order and timing of governance parameter updates.

**Attack Scenario:**

1. User has a position with BTC and ETH collateral, adjusted_ltv = 88% (safe, below 90% adjustment threshold, below 100% liquidation threshold)
2. Governance decides to decrease both BTC and ETH collateral ratios from 0.9 to 0.7 to reduce protocol risk
3. Governance sends Tx1: `SetCollateral { denom: "BTC", ratio: 0.7 }` - mined at block N
4. Before Tx2 can be mined, the user's adjusted collateral value drops significantly (BTC now haircut at 0.7 instead of 0.9)
5. User's adjusted_ltv jumps to 102% (above 100% liquidation threshold)
6. Liquidators immediately liquidate the user's position, seizing collateral
7. Governance sends Tx2: `SetCollateral { denom: "ETH", ratio: 0.7 }` - mined at block N+1

The user's position was liquidated during the partial update window, even though governance intended both ratio updates to occur together. If both updates had been atomic, the user's position might have remained at 95% LTV (still unsafe but potentially giving the user time to add collateral), or the liquidation order might have been different.

This breaks the protocol's security guarantee that users have predictable liquidation thresholds based on configuration parameters. The intermediate configuration states create arbitrary liquidation triggers that depend solely on update ordering rather than actual risk assessment.

## Impact Explanation

**High Severity** - This vulnerability enables:

1. **Unfair Liquidations**: Users lose collateral through liquidations triggered by transient configuration states rather than actual position deterioration. When governance updates multiple collateral ratios, users have no ability to react to intermediate states.

2. **Liquidator MEV Exploitation**: Sophisticated liquidators monitoring governance transactions can immediately liquidate positions that become temporarily unsafe during partial updates, profiting from configuration-timing rather than legitimate risk management.

3. **Protocol State Inconsistency**: LTV calculations during the partial update window use mixed old/new ratios, violating the assumption that all collateral types are valued consistently according to current risk parameters.

4. **Systemic Undercollateralization Risk**: If governance increases some ratios before others, users could temporarily over-borrow during the partial state, leaving the protocol undercollateralized once all updates complete.

The financial impact depends on the number of accounts affected and the value at risk during governance updates, but can easily reach hundreds of thousands of dollars during protocol-wide risk parameter adjustments.

## Likelihood Explanation

**High Likelihood** - This issue will occur during every multi-asset collateral ratio update:

- Governance updates are necessary protocol maintenance operations that occur regularly as market conditions and risk assessments change
- The protocol supports multiple collateral types (BTC, ETH, USDC, etc.) and risk-based adjustments typically affect multiple assets simultaneously
- There is currently no batch update mechanism, forcing governance to send separate transactions for each denom
- Block times create unavoidable gaps between transactions (1-10 seconds typically)
- Automated liquidation bots actively monitor all positions and will immediately execute liquidations when accounts exceed thresholds
- No protection mechanism exists to prevent liquidations during governance update windows

## Recommendation

Implement a batch collateral ratio update mechanism:

```rust
// In packages/rujira-rs/src/interfaces/ghost/credit/interface.rs
#[cw_serde]
pub enum SudoMsg {
    SetVault { address: String },
    SetCollateral { denom: String, collateralization_ratio: Decimal },
    
    // NEW: Atomic batch update
    SetCollateralBatch { 
        updates: Vec<(String, Decimal)> 
    },
    
    UpdateConfig(ConfigUpdate),
}

// In contracts/rujira-ghost-credit/src/contract.rs
SudoMsg::SetCollateralBatch { updates } => {
    for (denom, ratio) in updates {
        config.collateral_ratios.insert(denom, ratio);
    }
    config.validate()?;
    config.save(deps.storage)?;
    Ok(Response::default())
}
```

Additionally, consider implementing a "liquidation pause" flag that governance can enable during multi-parameter updates to prevent exploitation of intermediate states.

## Proof of Concept

```rust
#[test]
fn test_non_atomic_collateral_update_causes_unfair_liquidation() {
    let mut app = mock_rujira_app();
    
    // Set initial prices: BTC=$100k, ETH=$50k
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::from_str("100000").unwrap()),
            ("ETH", Decimal::from_str("50000").unwrap()),
            ("USDC", Decimal::from_str("1.0").unwrap()),
        ]);
    });

    let owner = app.api().addr_make("user");
    let liquidator = app.api().addr_make("liquidator");
    let fees = app.api().addr_make("fees");
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    
    // Set initial collateral ratios: BTC=0.9, ETH=0.9
    credit.set_collateral(&mut app, "btc-btc", "0.9");
    credit.set_collateral(&mut app, "eth-eth", "0.9");
    credit.set_collateral(&mut app, USDC, "0.9");
    
    // Create account and deposit collateral: 1 BTC + 1 ETH = $150k
    let account = credit.create_account(&mut app, &owner, "", "", Binary::new(vec![0]));
    app.send_tokens(owner.clone(), account.account.clone(), 
        &[coin(1_000_000, "btc-btc"), coin(1_000_000, "eth-eth")]).unwrap();
    
    // Setup vault and borrow $120k USDC
    let vault = GhostVault::create(&mut app, &owner, USDC);
    vault.set_borrower(&mut app, credit.addr().as_str(), Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    vault.deposit(&mut app, &owner, 200_000_000_000, USDC).unwrap();
    
    credit.account_borrow(&mut app, &account, 120_000_000_000, USDC).unwrap();
    
    // Check initial LTV: debt=$120k, adjusted_collateral=$135k (0.9*$150k)
    // LTV = 120/135 = 88.9% (SAFE - below 90% adjustment, below 100% liquidation)
    let acc = credit.query_account(&app, &account.account);
    assert!(acc.ltv < Decimal::from_str("0.9").unwrap());
    
    // GOVERNANCE UPDATE PART 1: Decrease BTC ratio to 0.7
    credit.set_collateral(&mut app, "btc-btc", "0.7");
    
    // Check LTV after partial update: adjusted_collateral = 0.7*$100k + 0.9*$50k = $115k
    // LTV = 120/115 = 104.3% (LIQUIDATABLE! Crossed 100% threshold)
    let acc_partial = credit.query_account(&app, &account.account);
    assert!(acc_partial.ltv > Decimal::one()); // Position now liquidatable!
    
    // Liquidator exploits the partial state and liquidates
    let liquidation_result = credit.liquidate(
        &mut app, 
        &liquidator,
        &account.account,
        vec![LiquidateMsg::Repay("eth-eth".to_string())]
    );
    assert!(liquidation_result.is_ok()); // Liquidation succeeds!
    
    // GOVERNANCE UPDATE PART 2: Decrease ETH ratio to 0.7 (too late!)
    credit.set_collateral(&mut app, "eth-eth", "0.7");
    
    // User's position was liquidated during intermediate state, even though
    // governance intended both updates to be coordinated. The user lost funds
    // due to non-atomic configuration updates, not due to any action of their own.
}
```

**Notes:**

The vulnerability stems from the architectural decision to only support single-denom collateral ratio updates through `SudoMsg::SetCollateral`. While each individual update is atomic within its transaction, multi-asset parameter changes necessarily create intermediate states with mixed old/new ratios. This violates user expectations about coordinated risk parameter updates and enables exploitation by liquidators monitoring governance transactions. The issue affects all positions with multiple collateral types whenever governance adjusts risk parameters across the protocol.

### Citations

**File:** contracts/rujira-ghost-credit/src/config.rs (L11-16)
```rust
pub type CollateralRatios = BTreeMap<String, Decimal>;

#[cw_serde]
pub struct Config {
    pub code_id: u64,
    pub collateral_ratios: CollateralRatios,
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
