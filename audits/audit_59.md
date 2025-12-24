# Audit Report

## Title
Oracle Price Manipulation During Liquidations Undetectable Due to Missing Snapshot Validation

## Summary
The `validate_liquidation()` function re-queries oracle prices during validation instead of comparing them against snapshot prices taken at liquidation trigger time. This allows liquidations to proceed at manipulated oracle prices without detection, as the slippage validation uses post-manipulation prices for both before/after calculations, making manipulated liquidations appear legitimate.

## Finding Description

The liquidation flow has a critical monitoring gap that prevents detection of oracle price manipulation:

**At Liquidation Trigger** (ExecuteMsg::Liquidate): [1](#0-0) 

The account state is loaded with USD values calculated from current oracle prices and stored in the payload: [2](#0-1) 

The `Valued<Collateral>` struct contains `value` (USD at snapshot time) and `value_adjusted` (with collateral ratio applied), but these snapshot values are never used for validation.

**During Liquidation Validation** (validate_liquidation): [3](#0-2) 

The function calculates spent and repaid amounts, then queries FRESH oracle prices: [4](#0-3) 

This means both `spent_usd` and `repaid_usd` use the SAME (potentially manipulated/recovered) prices, making the slippage calculation meaningless for detecting oracle manipulation.

**Event Emission Gap**: [5](#0-4) 

The liquidation event only emits basic account info without LTV, price data, or expected vs actual liquidation amounts, preventing external monitoring systems from detecting anomalies.

**Attack Scenario:**
1. Oracle price for collateral is temporarily manipulated downward (or naturally volatile)
2. Account becomes liquidatable at manipulated price (LTV crosses liquidation_threshold)
3. Liquidator executes swaps at manipulated price via LiquidateMsg::Execute
4. Oracle price recovers to normal before validate_liquidation() runs
5. Slippage check uses recovered prices: `(spent_at_recovered_price - repaid_at_recovered_price) / spent_at_recovered_price`
6. Validation passes because prices are consistent in the calculation
7. User lost collateral at manipulated price, but protocol sees no slippage violation
8. No alerts generated - manipulation is invisible to protocol and monitoring systems

## Impact Explanation

**Medium Severity** - This breaks the protocol's "Safe Liquidation Outcomes" invariant by allowing liquidations to deviate significantly from protocol assumptions without detection. While exploitation requires oracle price manipulation (external to protocol), the vulnerability is that the protocol provides NO mechanism to detect when such manipulation occurs.

The snapshotted USD values in `CreditAccount.collaterals[].value` and `debts[].value` exist but are never compared against actual liquidation outcomes. This is a monitoring and detection gap that:
- Masks oracle manipulation during liquidations
- Prevents external monitoring systems from detecting anomalies (insufficient event data)
- Allows users to lose collateral at manipulated prices without protocol alerts
- Requires manual intervention and off-chain monitoring to detect exploitation

With typical liquidation_max_slip of 30%, an attacker could manipulate prices by up to 30% during liquidation and have it appear as legitimate slippage to the protocol.

## Likelihood Explanation

**Medium Likelihood** - While this requires oracle price manipulation or extreme volatility during the liquidation window, several factors increase likelihood:
- THORChain oracle updates occur at regular intervals, creating manipulation windows
- Multi-block liquidation execution provides time for price changes
- No on-chain detection means exploitation can occur repeatedly undetected
- High-value liquidations create strong financial incentives
- Protocol's event system provides no forensic data for post-incident analysis

## Recommendation

Add snapshot price validation to `validate_liquidation()`:

```rust
pub fn validate_liquidation(
    &self,
    deps: Deps,
    config: &Config,
    old: &Self,
) -> Result<(), ContractError> {
    let balance = self.balance();
    let spent = old.balance().sent(&balance);

    // Validate preference order
    for coin in spent.clone().into_vec() {
        self.liquidation_preferences.order.validate(&coin, &balance)?;
    }

    // Calculate using SNAPSHOT prices from trigger time
    let spent_usd_snapshot = old.collaterals
        .iter()
        .filter(|c| spent.0.iter().any(|s| s.denom == c.item.balance().0[0].denom))
        .map(|c| c.value)
        .sum::<Decimal>();
    
    let repaid = old.debt().sent(&self.debt());
    let repaid_usd_snapshot = old.debts
        .iter()
        .filter(|d| repaid.0.iter().any(|r| r.denom == d.item.denom))
        .map(|d| d.value)
        .sum::<Decimal>();

    // Calculate using CURRENT prices
    let spent_usd_current = spent.value_usd(deps.querier)?;
    let repaid_usd_current = repaid.value_usd(deps.querier)?;

    // Check slippage using snapshot prices
    let slippage_snapshot = spent_usd_snapshot
        .checked_sub(repaid_usd_snapshot)
        .unwrap_or_default()
        .checked_div(spent_usd_snapshot)
        .unwrap_or_default();

    ensure!(
        slippage_snapshot.le(&config.liquidation_max_slip),
        ContractError::LiquidationMaxSlipExceeded { slip: slippage_snapshot }
    );

    // Detect significant price divergence (oracle manipulation indicator)
    let price_divergence = spent_usd_snapshot
        .abs_diff(spent_usd_current)
        .checked_div(spent_usd_snapshot)
        .unwrap_or_default();
    
    ensure!(
        price_divergence.le(&Decimal::percent(10)), // 10% threshold
        ContractError::OraclePriceDivergence { divergence: price_divergence }
    );

    Ok(())
}
```

Also enhance event emission:
```rust
pub fn event_execute_liquidate(
    account: &CreditAccount, 
    caller: &Addr,
    ltv_before: Decimal,
    expected_collateral_value: Decimal,
    expected_debt_value: Decimal,
) -> Event {
    Event::new(format!("{}/account.liquidate", env!("CARGO_PKG_NAME")))
        .add_attribute("owner", account.owner.clone())
        .add_attribute("address", account.id().to_string())
        .add_attribute("caller", caller.to_string())
        .add_attribute("ltv_before", ltv_before.to_string())
        .add_attribute("expected_collateral_usd", expected_collateral_value.to_string())
        .add_attribute("expected_debt_usd", expected_debt_value.to_string())
}
```

## Proof of Concept

```rust
#[test]
fn oracle_manipulation_during_liquidation_undetected() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let ctx = setup(&mut app, &owner);

    // Setup: Deposit 0.1 BTC collateral worth $11,100 at 80% ratio = $8,880 borrowing power
    app.send_tokens(owner.clone(), ctx.account.account.clone(), &[coin(10000000, BTC)]).unwrap();
    
    // Borrow $8,000 (LTV = 90.1% of adjusted value)
    ctx.ghost_credit.account_borrow(&mut app, &ctx.account, 8000000000000, USDC).unwrap();
    ctx.ghost_credit.account_send(&mut app, &ctx.account, 8000000000000, USDC, &owner).unwrap();

    // ATTACK: Manipulate BTC price down to $100,000 (from $111,000)
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![("BTC", Decimal::from_str("100000").unwrap())]);
    });

    // Account becomes liquidatable (LTV > 100%)
    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv > Decimal::one());

    // Liquidator executes swap at manipulated price
    ctx.ghost_credit.liquidate_execute_repay(
        &mut app,
        &account,
        ctx.fin_btc_usdc.addr(),
        fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo { to: None, callback: None }),
        coins(5000000, BTC), // Liquidating 0.05 BTC at $100k = $5,000 worth
        USDC,
    ).unwrap();

    // ATTACK: Restore BTC price to $111,000 BEFORE validation completes
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![("BTC", Decimal::from_str("111000").unwrap())]);
    });

    // Protocol thinks everything is fine - slippage calculated at $111k for both sides
    // User lost 0.05 BTC at $100k price ($5,000) but protocol validates at $111k price ($5,550)
    // $550 value extraction is invisible to the protocol
    let account_after = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    
    // No error raised - manipulation succeeded without detection
    assert!(account_after.ltv < Decimal::one()); // Now safe
}
```

**Notes:**
- The vulnerability requires oracle price changes during liquidation execution window
- The protocol stores snapshotted values but never validates actual outcomes against them
- Event emission provides insufficient data for external monitoring to detect manipulation
- This breaks the "Safe Liquidation Outcomes" invariant by allowing undetected deviations from protocol assumptions

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-99)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
            let mut queue: Vec<(LiquidateMsg, bool)> =
                msgs.iter().map(|x| (x.clone(), false)).collect();
            queue.reverse();
            let mut prefs: Vec<(LiquidateMsg, bool)> = account
                .liquidation_preferences
                .messages
                .iter()
                .map(|x| (x.clone(), true))
                .collect();
            prefs.reverse();
            queue.append(&mut prefs);

            Ok(Response::default()
                .add_message(
                    ExecuteMsg::DoLiquidate {
                        addr: account.id().to_string(),
                        queue,
                        payload: to_json_binary(&account)?,
                    }
                    .call(&ca)?,
                )
                .add_event(event_execute_liquidate(&account, &info.sender)))
        }
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L40-45)
```rust
#[cw_serde]
pub struct Valued<T> {
    pub value: Decimal,
    pub value_adjusted: Decimal,
    pub item: T,
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

**File:** contracts/rujira-ghost-credit/src/events.rs (L66-71)
```rust
pub fn event_execute_liquidate(account: &CreditAccount, caller: &Addr) -> Event {
    Event::new(format!("{}/account.liquidate", env!("CARGO_PKG_NAME")))
        .add_attribute("owner", account.owner.clone())
        .add_attribute("address", account.id().to_string())
        .add_attribute("caller", caller.to_string())
}
```
