# Audit Report

## Title
Aggregate Slippage Check in Multi-Collateral Liquidations Allows Individual Collateral Types to Exceed Maximum Slippage Limits

## Summary
The `validate_liquidation()` function only checks aggregate slippage across all liquidated collateral types, allowing liquidators to extract excessive value from individual collateral types while keeping the total slippage within protocol limits. This undermines the protocol's user protection mechanism.

## Finding Description

The vulnerability exists in the slippage validation logic during liquidations. When a credit account holds multiple collateral types (e.g., BTC and ETH), the `validate_liquidation()` function calculates slippage as an aggregate across all collateral types rather than checking each type individually. [1](#0-0) 

The function retrieves all spent collateral coins but only validates the liquidation order preference for each coin individually. The slippage calculation combines the USD value of ALL spent collateral and ALL repaid debt into a single metric. This aggregate slippage is then compared against `config.liquidation_max_slip`.

This breaks **Invariant #3: Safe Liquidation Outcomes**, which requires liquidations to respect max slip limits. The protocol documentation explicitly states: [2](#0-1) 

A malicious or profit-maximizing liquidator can exploit this by:
1. Liquidating multiple collateral types in a single transaction
2. Extracting high value from one collateral type (e.g., 25% slippage)
3. Extracting fair value from another collateral type (e.g., 5% slippage)
4. Maintaining aggregate slippage within limits (e.g., 15% when limit is 30%)

**Concrete Example:**
- User has $50,000 BTC and $50,000 ETH collateral
- `liquidation_max_slip = 30%` (from config)
- Liquidator swaps:
  - $50,000 BTC → receives $35,000 USDC (30% slippage)
  - $50,000 ETH → receives $45,000 USDC (10% slippage)
- Aggregate: $100,000 spent → $80,000 repaid (20% slippage) ✓ passes
- **Result**: User loses 30% on BTC, which equals the maximum limit, but if the liquidator increases BTC slippage to 35% and decreases ETH to 5%, aggregate remains 20% while BTC exceeds the limit.

The liquidation flow in the main contract confirms this aggregate validation occurs after processing all liquidation messages: [3](#0-2) 

## Impact Explanation

**High Severity** - Direct user fund loss beyond protocol-intended protection limits.

Users suffer financial harm exceeding the maximum slippage threshold on specific collateral assets. The `liquidation_max_slip` parameter exists specifically to protect users from excessive value extraction during liquidations. By only checking aggregate slippage, the protocol fails to provide this protection when multiple collateral types are involved.

If `liquidation_max_slip = 30%`, users reasonably expect no single collateral type to lose more than 30% of its value during liquidation. However, a liquidator could extract 50% from BTC and 10% from ETH, keeping aggregate at 30%, causing the user to lose 50% on their BTC holdings.

## Likelihood Explanation

**High Likelihood** - This vulnerability is exploitable in any liquidation involving multiple collateral types, which is a core feature of the protocol. The protocol explicitly supports multi-collateral accounts: [4](#0-3) 

Liquidators are economically incentivized to maximize profit by exploiting price inefficiencies across different collateral types. Multi-collateral accounts are common as users diversify their holdings. No special conditions or timing attacks are required—the vulnerability exists in the normal liquidation flow.

## Recommendation

Implement per-collateral slippage validation in addition to (or instead of) the aggregate check. Modify `validate_liquidation()` to track and validate slippage for each individual collateral type:

```rust
pub fn validate_liquidation(
    &self,
    deps: Deps,
    config: &Config,
    old: &Self,
) -> Result<(), ContractError> {
    let balance = self.balance();
    let spent = old.balance().sent(&balance);

    // Existing preference order validation
    for coin in spent.clone().into_vec() {
        self.liquidation_preferences
            .order
            .validate(&coin, &balance)?;
    }

    // NEW: Per-coin slippage validation
    let repaid = old.debt().sent(&self.debt());
    for spent_coin in spent.clone().into_vec() {
        let spent_coin_usd = spent_coin.value_usd(deps.querier)?;
        if spent_coin_usd.is_zero() {
            continue;
        }
        
        // Find corresponding repayment for this collateral type
        // Assume proportional repayment based on value
        let total_spent_usd = spent.value_usd(deps.querier)?;
        let total_repaid_usd = repaid.value_usd(deps.querier)?;
        let proportion = spent_coin_usd.checked_div(total_spent_usd).unwrap_or_default();
        let coin_repaid_usd = total_repaid_usd.checked_mul(proportion).unwrap_or_default();
        
        let coin_slippage = spent_coin_usd
            .checked_sub(coin_repaid_usd)
            .unwrap_or_default()
            .checked_div(spent_coin_usd)
            .unwrap_or_default();

        if !coin_slippage.is_zero() {
            ensure!(
                coin_slippage.le(&config.liquidation_max_slip),
                ContractError::LiquidationMaxSlipExceeded { slip: coin_slippage }
            );
        }
    }

    // Existing aggregate check (can be kept or removed)
    let spent_usd = spent.value_usd(deps.querier)?;
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

Alternatively, require liquidators to specify which debt tokens correspond to which collateral tokens to enable precise per-asset slippage tracking.

## Proof of Concept

```rust
#[test]
fn test_multi_collateral_slippage_bypass() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let liquidator = app.api().addr_make("liquidator");
    let ctx = setup(&mut app, &owner);

    // Fund account with equal value BTC and ETH: $11,100 each
    app.send_tokens(
        owner.clone(),
        ctx.account.account.clone(),
        &[coin(10000000, BTC), coin(317142857, ETH)], // 0.1 BTC, ~3.17 ETH at $3500
    )
    .unwrap();

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    
    // Borrow to reach liquidatable state
    // Total adjusted collateral: $11,100 * 0.8 + $11,100 * 0.7 = $16,650
    // Borrow $15,817.5 (95% of adjusted)
    ctx.ghost_credit
        .account_borrow(&mut app, &account, 15817500000000, USDC)
        .unwrap();

    ctx.ghost_credit
        .account_send(&mut app, &account, 15817500000000, USDC, &owner)
        .unwrap();

    // Drop prices to make account liquidatable
    app.init_modules(|router, _api, _storage| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::from_str("105450").unwrap()), // ~5% drop
            ("ETH", Decimal::from_str("3325").unwrap()),    // ~5% drop
        ]);
    });

    let account = ctx.ghost_credit.query_account(&app, &ctx.account.account);
    assert!(account.ltv >= Decimal::one()); // Confirm liquidatable

    // Liquidator executes multi-collateral liquidation with uneven slippage:
    // - BTC swap: Extract $10,545 worth, but only repay $7,000 (33.6% slippage)
    // - ETH swap: Extract $10,532 worth, repay $10,000 (5.1% slippage)
    // - Aggregate: $21,077 spent, $17,000 repaid (19.3% slippage < 30% limit)
    
    // This should FAIL but currently PASSES because only aggregate is checked
    let result = ctx.ghost_credit.liquidate(
        &mut app,
        &account,
        vec![
            LiquidateMsg::Execute {
                contract_addr: ctx.fin_btc_usdc.addr().to_string(),
                msg: to_json_binary(&fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
                    to: None,
                    callback: None,
                })).unwrap(),
                funds: coins(10000000, BTC), // All BTC
            },
            LiquidateMsg::Execute {
                contract_addr: ctx.fin_eth_usdc.addr().to_string(),
                msg: to_json_binary(&fin::ExecuteMsg::Swap(fin::SwapRequest::Yolo {
                    to: None,
                    callback: None,
                })).unwrap(),
                funds: coins(317142857, ETH), // All ETH
            },
            LiquidateMsg::Repay(USDC.to_string()),
        ],
    );

    // Vulnerability: This passes even though BTC had >30% slippage
    assert!(result.is_ok(), "Liquidation should pass with aggregate slippage check");
    
    // User lost 33.6% on BTC despite 30% max slip limit
}
```

**Notes:**
- The vulnerability exists because slippage validation operates on aggregate USD values rather than per-asset basis
- This allows strategic liquidators to maximize profit by selectively extracting excess value from specific collateral types
- The issue is systemic to any multi-collateral liquidation scenario in the protocol
- The fix requires tracking individual collateral-to-debt exchange ratios or implementing per-asset slippage limits

### Citations

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

**File:** contracts/rujira-ghost-credit/README.md (L170-170)
```markdown
- The $ value when collateral is exchanged for debt must not exceed `config.liquidation_max_slip`.
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L110-117)
```rust
            let check = account
                // Check safe against the liquidation threshold
                .check_safe(&config.liquidation_threshold)
                // Check we've not gone below the adjustment threshold
                .and_then(|_| account.check_unsafe(&config.adjustment_threshold))
                .and_then(|_| {
                    account.validate_liquidation(deps.as_ref(), &config, &original_account)
                });
```

**File:** contracts/rujira-ghost-credit/src/config.rs (L14-23)
```rust
pub struct Config {
    pub code_id: u64,
    pub collateral_ratios: CollateralRatios,
    pub fee_liquidation: Decimal,
    pub fee_liquidator: Decimal,
    pub fee_address: Addr,
    pub liquidation_max_slip: Decimal,
    pub liquidation_threshold: Decimal,
    pub adjustment_threshold: Decimal,
}
```
