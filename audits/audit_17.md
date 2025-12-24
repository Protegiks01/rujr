# Audit Report

## Title
Oracle Query Failure in to_credit_account() Causes Complete Protocol DoS and Prevents All Liquidations

## Summary
The `to_credit_account()` function iterates through ALL configured collateral types and queries oracle prices for each, even for collaterals an account doesn't hold. If any oracle query fails (unsupported denom, oracle downtime, ticker delisted), the entire function fails with the `?` operator, preventing account loading, liquidations, user operations, and safety checks across the ENTIRE protocol.

## Finding Description

In `to_credit_account()`, the function iterates through all collateral types in `config.collateral_ratios` to build the credit account state: [1](#0-0) 

The critical flaw is at line 302: `if item.value_usd(deps.querier)?.is_zero()`. This line queries the oracle price for EVERY configured collateral type, not just the ones an account holds. The `?` operator propagates any error upward, causing the entire function to fail.

The `value_usd()` method calls through to `OraclePrice::load()`: [2](#0-1) [3](#0-2) 

Oracle price queries can fail when:
1. The ticker is not found in the oracle (returns `TryFromOraclePriceError::NotFound`)
2. Oracle experiences downtime (returns `QueryError`)
3. The denom cannot be parsed as a valid secured asset

The `to_credit_account()` function is called by `CreditAccount::load()`: [4](#0-3) 

Which is invoked in ALL critical protocol operations:

**Liquidation Initiation:** [5](#0-4) 

**Liquidation Execution:** [6](#0-5) 

**User Account Operations:** [7](#0-6) 

**Post-Operation Safety Checks:** [8](#0-7) 

**Account Queries:** [9](#0-8) 

Governance can add collateral types via `SudoMsg::SetCollateral`: [10](#0-9) 

**Attack Scenario:**
1. Governance adds collateral type "eth-newtoken" to `collateral_ratios` 
2. Users create accounts and deposit various collaterals (btc-btc, eth-eth, etc.)
3. Some accounts become underwater (LTV > liquidation_threshold)
4. THORChain oracle removes "NEWTOKEN" ticker or experiences downtime for that asset
5. Now ANY attempt to load ANY account (regardless of which collaterals they hold) fails at line 302
6. Liquidations cannot be initiated or executed → protocol becomes insolvent
7. Users cannot perform ANY operations (borrow, repay, send) → funds permanently frozen
8. Safety checks cannot execute → protocol cannot enforce LTV limits

**Broken Invariants:**
- **Invariant #2**: "Post-Adjustment LTV Check: After any owner operation, adjusted_ltv must be < adjustment_threshold" - Cannot be enforced because `CheckAccount` fails
- **Invariant #3**: "Safe Liquidation Outcomes: Liquidations only trigger when adjusted_ltv >= liquidation_threshold" - Cannot occur because liquidations fail to load accounts

## Impact Explanation

**CRITICAL Severity - Protocol Insolvency and Permanent Fund Freezing:**

1. **Protocol Insolvency**: Underwater accounts cannot be liquidated when oracle fails for ANY configured collateral. Bad debt accumulates, protocol becomes insolvent, lenders lose funds.

2. **Permanent Fund Freezing**: Users cannot perform ANY account operations (borrow, repay, execute, send, transfer) if oracle fails for ANY configured collateral, even if they don't hold that collateral. Their funds are permanently locked unless protocol is redeployed.

3. **Safety Check Bypass**: The post-operation LTV safety check (`ExecuteMsg::CheckAccount`) fails, meaning the protocol cannot enforce the critical invariant that `adjusted_ltv < adjustment_threshold`. This allows unsafe account states to persist.

4. **Complete Protocol DoS**: All queries fail, UI breaks, monitoring systems fail, protocol becomes completely unusable.

5. **Cascading Failure**: A single collateral's oracle failure affects ALL accounts across the entire protocol, not just accounts holding that specific collateral.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Accidental Trigger**: Oracle providers commonly delist tickers, experience downtime, or deprecate assets. This is not a theoretical attack - it's a realistic operational risk.

2. **No Attack Required**: This vulnerability can manifest without any malicious actor. Simple oracle maintenance or network issues trigger it.

3. **Broad Attack Surface**: ANY configured collateral experiencing oracle issues breaks the entire protocol.

4. **No Time Constraint**: Once triggered, the DoS persists until either the oracle is restored OR the protocol is redeployed (requiring migration).

5. **Historical Precedent**: DeFi protocols have experienced oracle downtimes and ticker delistings numerous times (Chainlink pausing feeds, API provider outages, etc.).

## Recommendation

Modify `to_credit_account()` to gracefully handle oracle failures instead of propagating errors. Only query oracle prices for collaterals the account actually holds (non-zero balance):

```rust
for denom in config.collateral_ratios.keys() {
    let balance = deps.querier.query_balance(&self.account, denom)?;
    
    // Skip if account has no balance of this collateral
    if balance.amount.is_zero() {
        continue;
    }
    
    let item = Collateral::try_from(&balance)?;
    
    // Now query oracle only for held collaterals
    // Wrap in match to handle oracle failures gracefully
    match item.value_usd(deps.querier) {
        Ok(value) if value.is_zero() => continue,
        Ok(value) => {
            ca.collaterals.push(Valued {
                value,
                value_adjusted: item.value_adjusted(deps, &config.collateral_ratios)?,
                item,
            });
        }
        Err(_) => {
            // Log error but continue - don't block account operations
            // This collateral will be excluded from LTV calculation
            continue;
        }
    }
}
```

Additionally, implement a circuit breaker mechanism:
- Allow governance to temporarily disable problematic collaterals without blocking all operations
- Add a flag to `collateral_ratios` entries to mark them as "oracle_disabled"
- Skip oracle queries for disabled collaterals but still allow account operations

## Proof of Concept

```rust
#[test]
fn test_oracle_failure_blocks_all_operations() {
    let mut app = mock_rujira_app();
    
    // Initialize with working oracle for BTC and ETH
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("BTC", Decimal::from_str("50000").unwrap()),
            ("ETH", Decimal::from_str("3000").unwrap()),
        ]);
    });
    
    let owner = app.api().addr_make("owner");
    let fees = app.api().addr_make("fee");
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    
    // Add BTC and ETH as collaterals
    credit.set_collateral(&mut app, BTC, Decimal::from_str("0.9").unwrap());
    credit.set_collateral(&mut app, ETH, Decimal::from_str("0.9").unwrap());
    
    // User creates account with BTC collateral only
    let account = credit.create_account(&mut app, &owner, "", "", Binary::new(vec![0]));
    app.execute(
        owner.clone(),
        account.account.clone(),
        &[coin(100000, BTC)],
        &[],
    ).unwrap();
    
    // Account works fine - can query it
    let acc = credit.query_account(&app, &account.account);
    assert_eq!(acc.collaterals.len(), 1);
    assert_eq!(acc.collaterals[0].collateral, Collateral::Coin(coin(100000, BTC)));
    
    // Now add USDC as collateral but DON'T add oracle price for it
    credit.set_collateral(&mut app, USDC, Decimal::from_str("0.95").unwrap());
    
    // Oracle query will fail for USDC because no price is set
    // This should break ALL account operations, even though this account has no USDC
    
    // Try to query the account - should fail
    let result = credit.try_query_account(&app, &account.account);
    assert!(result.is_err(), "Query should fail due to missing USDC oracle price");
    
    // Try to liquidate an underwater account - should fail
    app.init_modules(|router, _, _| {
        router.stargate.with_price("BTC", Decimal::from_str("1").unwrap());
    });
    
    let liquidator = app.api().addr_make("liquidator");
    let result = app.execute_contract(
        liquidator,
        credit.addr(),
        &ExecuteMsg::Liquidate {
            addr: account.account.to_string(),
            msgs: vec![],
        },
        &[],
    );
    assert!(result.is_err(), "Liquidation should fail due to missing USDC oracle price");
    
    // Try user operations - should fail
    let result = app.execute_contract(
        owner.clone(),
        credit.addr(),
        &ExecuteMsg::Account {
            addr: account.account.to_string(),
            msgs: vec![AccountMsg::Send {
                to_address: owner.to_string(),
                funds: vec![coin(1000, BTC)],
            }],
        },
        &[],
    );
    assert!(result.is_err(), "User operations should fail due to missing USDC oracle price");
}
```

**Notes:**
- This vulnerability affects the entire protocol, not individual accounts
- The root cause is querying oracle prices for ALL configured collaterals, not just held ones
- Fix requires checking balance BEFORE querying oracle and handling oracle errors gracefully
- A single collateral's oracle failure creates a complete protocol-wide DoS
- This breaks critical protocol invariants around LTV enforcement and liquidation safety

### Citations

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

**File:** contracts/rujira-ghost-credit/src/account.rs (L300-310)
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
        }
```

**File:** packages/rujira-rs/src/oracle.rs (L56-61)
```rust
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L73-76)
```rust
        ExecuteMsg::Liquidate { addr, msgs } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L106-108)
```rust
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            let original_account: CreditAccount = from_json(&payload)?;
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L151-154)
```rust
        ExecuteMsg::Account { addr, msgs } => {
            let mut account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            ensure_eq!(account.owner, info.sender, ContractError::Unauthorized {});
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L165-169)
```rust
        ExecuteMsg::CheckAccount { addr } => {
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_safe(&config.adjustment_threshold)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L369-378)
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
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L406-413)
```rust
        QueryMsg::Account(addr) => Ok(to_json_binary(&AccountResponse::from(
            CreditAccount::load(
                deps,
                &config,
                &env.contract.address,
                deps.api.addr_validate(&addr)?,
            )?,
        ))?),
```
