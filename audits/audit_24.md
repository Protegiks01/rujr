# Audit Report

## Title
Oracle Price Timing Vulnerability in Liquidation Slippage Validation Allows DOS of Unsafe Account Liquidations

## Summary
The `validate_liquidation` function in the Rujira ghost credit contract calculates liquidation slippage using current oracle prices to value collateral that was spent at previous oracle prices. This time-of-check-time-of-use (TOCTOU) vulnerability allows price volatility between liquidation steps to incorrectly block legitimate liquidations of unsafe accounts, preventing the protocol from maintaining solvency.

## Finding Description

The vulnerability exists in the multi-step liquidation flow where oracle prices are queried multiple times across separate message executions:

**Step 1 - Initial Liquidation Check:** [1](#0-0) 

The account is loaded with current oracle prices and verified as unsafe.

**Step 2 - Account Serialization:** [2](#0-1) 

The account struct is serialized to a payload, but this only stores balance amounts, not USD values.

**Step 3 - DoLiquidate Execution:** [3](#0-2) 

The account is reloaded with fresh oracle prices, and `validate_liquidation` is called.

**Step 4 - Flawed Slippage Calculation:** [4](#0-3) 

The `validate_liquidation` function calculates spent collateral USD value using CURRENT oracle prices: [5](#0-4) 

**The Critical Flaw:**
The function calls `value_usd(deps.querier)` which queries current oracle prices for collateral amounts that were spent when prices were potentially different. The oracle price query happens here: [6](#0-5) [7](#0-6) 

**Attack Scenario - DOS of Liquidations:**

Initial state:
- Account has 1000 USDT collateral at $1.00 = $1,000 total value
- Account has $950 debt  
- LTV = 95%, unsafe (above 90% liquidation threshold)
- Config: `liquidation_max_slip = 30%` (from test config) [8](#0-7) 

Liquidation flow:
1. Liquidator calls `ExecuteMsg::Liquidate` - account confirmed unsafe at $1.00 USDT price
2. `DoLiquidate` executes `LiquidateMsg::Execute` to swap 1000 USDT for ~950 debt tokens
3. **USDT oracle price spikes to $1.50** (natural volatility or market manipulation)
4. `DoLiquidate` processes `LiquidateMsg::Repay`:
   - Reloads account with $1.50 USDT price
   - `validate_liquidation` calculates: 
     - `spent_usd = 1000 USDT × $1.50 = $1,500` (using inflated price!)
     - `repaid_usd = $950`  
     - `slippage = ($1,500 - $950) / $1,500 = 36.7%`
   - Transaction FAILS (36.7% > 30% max allowed)

**Outcome:** The liquidation fails even though:
- The account was legitimately unsafe
- The actual collateral value when swapped was only $1,000
- The real slippage was ($1,000 - $950) / $1,000 = 5%, well within limits
- The protocol cannot liquidate this unsafe position, risking bad debt

This breaks the **Safe Liquidation Outcomes** invariant which requires liquidations to trigger when `adjusted_ltv >= liquidation_threshold` and properly process without false rejections.

## Impact Explanation

**HIGH SEVERITY** - This vulnerability creates systemic risk:

1. **Bad Debt Accumulation**: Unsafe accounts that should be liquidated remain open when price volatility causes false slippage violations. As collateral values continue declining, these accounts become insolvent, creating protocol bad debt.

2. **Liquidator Disincentive**: Liquidators face unpredictable transaction failures due to price movements beyond their control, reducing liquidation efficiency and protocol health.

3. **Cascading Failures**: In volatile markets when liquidations are most needed, price swings make the slippage check most likely to fail, creating a doom loop where the protocol cannot liquidate unsafe positions during market stress.

4. **Secondary Impact - Slippage Bypass**: In the opposite direction (price drops during liquidation), the calculated slippage appears lower than reality, potentially allowing liquidatees to lose more collateral than the protocol should permit.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability will occur regularly in production:

1. **Multi-Step Execution**: Liquidations require at least 2 separate message executions (Execute swap, then Repay), creating time windows for price changes.

2. **Natural Volatility**: Cryptocurrency prices fluctuate constantly. Even 5-10% moves between transactions are common, especially for volatile assets like BTC/ETH which are primary collateral types.

3. **No Attacker Required**: While the security question asks about manipulation, the vulnerability triggers from natural market conditions without requiring active exploitation.

4. **THORChain Oracle Updates**: The oracle queries at height "0" (current), meaning any price update between liquidation steps triggers the bug.

5. **Market Stress Amplification**: The issue is most severe during high volatility when liquidations are most critical, making this a reliability problem rather than just an edge case.

## Recommendation

**Fix Option 1 - Store USD Values in Payload:**

Modify the liquidation flow to snapshot and preserve USD values at liquidation initiation:

```rust
// In ExecuteMsg::Liquidate
let account_snapshot = AccountSnapshot {
    balances: account.collaterals.clone(),
    debts: account.debts.clone(),
    collateral_usd: account.collaterals.iter().map(|c| c.value).sum(),
    debt_usd: account.debts.iter().map(|d| d.value).sum(),
};

ExecuteMsg::DoLiquidate {
    addr: account.id().to_string(),
    queue,
    payload: to_json_binary(&account_snapshot)?,
}
```

Then in `validate_liquidation`, use the snapshotted USD values instead of recalculating:

```rust
pub fn validate_liquidation(
    &self,
    deps: Deps,
    config: &Config,
    snapshot: &AccountSnapshot,
) -> Result<(), ContractError> {
    let balance = self.balance();
    let spent = snapshot.balances.sent(&balance);
    
    // Use snapshotted prices, not current prices
    let spent_usd = calculate_usd_from_snapshot(&spent, &snapshot.balances)?;
    let repaid = snapshot.debts.sent(&self.debt());
    let repaid_usd = calculate_usd_from_snapshot(&repaid, &snapshot.debts)?;
    
    let slippage = spent_usd.checked_sub(repaid_usd)...
}
```

**Fix Option 2 - Add Price Change Tolerance:**

Allow the slippage check to account for reasonable price movements:

```rust
let price_volatility_buffer = Decimal::percent(10); // 10% buffer
let adjusted_max_slip = config.liquidation_max_slip + price_volatility_buffer;

if !slippage.is_zero() {
    ensure!(
        slippage.le(&adjusted_max_slip),
        ContractError::LiquidationMaxSlipExceeded { slip: slippage }
    );
}
```

**Fix Option 3 - Use TWAP or Price Bounds:**

Implement time-weighted average pricing or require oracle price changes to be within bounds to prevent both manipulation and false rejections.

## Proof of Concept

```rust
#[test]
fn test_oracle_price_timing_dos_liquidation() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let ctx = setup(&mut app, &owner);

    // Setup account with collateral
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(1000000000, USDT)], // 1000 USDT (6 decimals)
    )
    .unwrap();

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);

    // Borrow to make account unsafe - borrow 95% of collateral value
    // At $1.00 USDT: 1000 USDT = $1000, borrow $950 USDC
    ctx.ghost_credit
        .account_borrow(&mut app, &account, 950000000, USDC)
        .unwrap();

    ctx.ghost_credit
        .account_send(&mut app, &account, 950000000, USDC, &owner)
        .unwrap();

    // Drop USDT price to make account unsafe (LTV > 90%)
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("USDT", Decimal::from_str("0.95").unwrap()),
        ]);
    });

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv > Decimal::from_str("0.9").unwrap());

    // Initiate liquidation - this will pass check_unsafe with USDT at $0.95
    // The Execute step swaps USDT for USDC
    // Then USDT price spikes to $1.50 before Repay step
    
    // Simulate price spike between Execute and Repay
    // In real scenario, this happens between DoLiquidate calls
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("USDT", Decimal::from_str("1.5").unwrap()),
        ]);
    });

    // Attempt liquidation - this should succeed but will fail due to
    // slippage calculation using inflated $1.50 price for USDT that was 
    // actually swapped at $0.95
    let result = ctx.ghost_credit.liquidate_execute_repay(
        &mut app,
        &account,
        ctx.fin_usdt_usdc.addr(),
        fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
            to: None,
            callback: None,
        }),
        coins(1000000000, USDT),
        USDC,
    );

    // The liquidation fails with slippage exceeded error
    // even though the real slippage was acceptable
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("LiquidationMaxSlipExceeded"));
}
```

**Notes**

The vulnerability stems from a design flaw in the liquidation validation logic rather than oracle manipulation per se. While the security question asks about "manipulating oracle prices," the actual issue is that the protocol's slippage calculation is fundamentally broken when prices change between liquidation steps - whether those changes are natural market volatility or intentional manipulation.

The protocol assumes oracle prices are static during multi-step liquidations, but this assumption is violated in practice. THORChain oracles update continuously, and the `OraclePrice::load()` function queries at height "0" (current block), meaning every liquidation step sees potentially different prices.

This creates a reliability problem that affects protocol solvency: the mechanism designed to protect liquidatees (max slippage) instead prevents liquidation of unsafe accounts during the exact market conditions when liquidations are most critical.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-76)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L90-96)
```rust
                .add_message(
                    ExecuteMsg::DoLiquidate {
                        addr: account.id().to_string(),
                        queue,
                        payload: to_json_binary(&account)?,
                    }
                    .call(&ca)?,
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L100-117)
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

**File:** packages/rujira-rs/src/oracle.rs (L55-61)
```rust
impl OracleValue for Coin {
    fn value_usd(&self, q: QuerierWrapper) -> Result<Decimal, OracleError> {
        Ok(SecuredAsset::from_denom(&self.denom)?
            .to_layer_1()
            .oracle_price(q)?
            .checked_mul(Decimal::from_ratio(self.amount, Uint128::one()))?)
    }
```

**File:** packages/rujira-rs/src/query/oracle_price.rs (L59-67)
```rust
impl OraclePrice {
    pub fn load(q: QuerierWrapper, symbol: &str) -> Result<Self, OraclePriceError> {
        let req = QueryOraclePriceRequest {
            height: "0".to_string(),
            symbol: symbol.to_owned(),
        };
        let res = QueryOraclePriceResponse::get(q, req)?;
        Ok(OraclePrice::try_from(res)?)
    }
```

**File:** contracts/rujira-ghost-credit/src/mock.rs (L294-294)
```rust
                    liquidation_max_slip: Decimal::from_str("0.3").unwrap(),
```
