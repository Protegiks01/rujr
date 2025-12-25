# Audit Report

## Title
Oracle Query Failure in to_credit_account() Causes Complete Protocol DoS and Prevents All Liquidations

## Summary
The `to_credit_account()` function queries oracle prices for ALL configured collateral types before checking if an account holds zero balance of those collaterals. If any oracle query fails (ticker delisting, downtime, or unsupported denom), the entire protocol becomes inoperable, preventing liquidations and freezing user funds permanently.

## Finding Description

The critical flaw exists in the `to_credit_account()` function which iterates through ALL configured collateral denoms in `config.collateral_ratios.keys()`: [1](#0-0) 

At line 302, the code calls `item.value_usd(deps.querier)?` to check if the value is zero. However, this queries the oracle price BEFORE determining whether the account actually holds any balance of that collateral. The oracle query chain is:

1. `value_usd()` for Collateral calls `Coin::value_usd()`: [2](#0-1) 

2. `Coin::value_usd()` calls `oracle_price(q)?` before multiplying by amount: [3](#0-2) 

3. `OraclePrice::load()` makes a GRPC query that can fail: [4](#0-3) 

When the oracle returns `None` or the query fails, it returns `TryFromOraclePriceError::NotFound`: [5](#0-4) 

The `?` operator at line 302 propagates this error, causing the entire `to_credit_account()` function to fail. This function is called by `CreditAccount::load()`: [6](#0-5) 

**ALL critical protocol operations call `CreditAccount::load()`:**

**Liquidation Initiation:** [7](#0-6) 

**Liquidation Execution:** [8](#0-7) 

**User Account Operations (borrow, repay, send, execute, transfer):** [9](#0-8) 

**Post-Operation Safety Checks:** [10](#0-9) 

**Account Queries:** [11](#0-10) 

Governance can add new collateral types via `SudoMsg::SetCollateral`: [12](#0-11) 

**Realistic Scenario:**
1. Governance adds collateral "eth-newtoken" to `collateral_ratios`
2. Users create accounts with various collaterals (btc-btc, eth-eth, etc.)
3. Some accounts become underwater (LTV > liquidation_threshold)
4. THORChain oracle removes "NEWTOKEN" ticker due to delisting or experiences downtime
5. Now ANY attempt to load ANY account fails at line 302, regardless of which collaterals they hold
6. Liquidations cannot execute → protocol becomes insolvent with accumulating bad debt
7. Users cannot perform ANY operations → funds are permanently frozen
8. Safety checks cannot execute → protocol cannot enforce LTV invariants

## Impact Explanation

**CRITICAL Severity - This causes multiple catastrophic failures:**

1. **Protocol Insolvency**: When oracle fails for ANY configured collateral, ALL liquidations are blocked. Underwater accounts cannot be liquidated, bad debt accumulates across the protocol, and lenders suffer losses. This violates **Invariant #3**: "Safe Liquidation Outcomes: Liquidations only trigger when adjusted_ltv >= liquidation_threshold" - because liquidations cannot trigger at all.

2. **Permanent Fund Freezing**: Users cannot perform ANY account operations (borrow, repay, execute, send, transfer) if oracle fails for ANY configured collateral, even if they don't hold that collateral. Their funds remain locked until either the oracle is restored OR the entire protocol is redeployed with migration.

3. **Safety Check Bypass**: The post-operation LTV safety check (`ExecuteMsg::CheckAccount`) fails, preventing enforcement of **Invariant #2**: "Post-Adjustment LTV Check: After any owner operation, adjusted_ltv must be < adjustment_threshold". This allows unsafe account states to persist indefinitely.

4. **Complete Protocol DoS**: All account queries fail, UI becomes non-functional, monitoring systems cannot track positions, and the protocol becomes completely unusable.

5. **Cascading Systemic Failure**: A single collateral's oracle failure affects ALL accounts across the entire protocol, not just accounts holding that specific collateral. This creates a single point of failure.

## Likelihood Explanation

**HIGH Likelihood:**

1. **Realistic Operational Risk**: Oracle providers commonly delist tickers, experience temporary downtime, or deprecate assets. This is NOT a theoretical attack requiring malicious actors - it's a realistic operational scenario.

2. **Historical Precedent**: DeFi protocols have repeatedly experienced oracle downtimes (Chainlink pausing feeds, API provider outages, exchange maintenance periods). This is well-documented in production environments.

3. **Broad Attack Surface**: ANY of the configured collateral types experiencing oracle issues triggers the vulnerability. The more collateral types added, the higher the probability.

4. **No Attacker Required**: This vulnerability manifests through normal operational issues without any malicious intent. Simple oracle maintenance or network issues trigger it.

5. **Persistent DoS**: Once triggered, the DoS persists until either the oracle feed is restored OR the protocol undergoes emergency redeployment with full migration, both of which take significant time.

## Recommendation

Check if the balance is zero BEFORE querying the oracle price. Modify `to_credit_account()` as follows:

```rust
for denom in config.collateral_ratios.keys() {
    let coin = deps.querier.query_balance(&self.account, denom)?;
    
    // Skip oracle query if balance is zero
    if coin.amount.is_zero() {
        continue;
    }
    
    let item = Collateral::try_from(&coin)?;
    // Only query oracle for non-zero balances
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

This ensures oracle queries are only made for collaterals the account actually holds, eliminating the single point of failure.

## Proof of Concept

While a complete integration test would require mocking THORChain oracle failures, the vulnerability can be demonstrated by examining the code flow:

1. User creates account with BTC collateral only
2. Governance adds ETH collateral to protocol
3. Oracle feed for ETH experiences downtime
4. User attempts to borrow against their BTC
5. `CreditAccount::load()` calls `to_credit_account()`
6. Loop iterates through both BTC and ETH denoms
7. ETH balance query returns 0 amount
8. Line 302 calls `value_usd()` which queries ETH oracle
9. Oracle query fails with `QueryError` or `NotFound`
10. `?` operator propagates error, entire transaction reverts
11. User's BTC collateral is now frozen despite having nothing to do with ETH

The critical insight is that line 302 in `account.rs` performs the oracle query BEFORE the zero-check, creating a mandatory dependency on ALL configured collateral oracles regardless of actual holdings.

## Notes

This vulnerability is distinct from oracle manipulation attacks. THORChain oracle providers are trusted (not assumed malicious), but operational issues like downtime, ticker delisting, or maintenance windows are realistic events that must be handled gracefully. The protocol should be resilient to individual oracle failures, not create a single point of failure across all accounts.

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

**File:** packages/rujira-rs/src/interfaces/ghost/credit/collateral.rs (L38-44)
```rust
impl OracleValue for Collateral {
    fn value_usd(&self, q: cosmwasm_std::QuerierWrapper) -> Result<Decimal, OracleError> {
        match self {
            Collateral::Coin(coin) => Ok(coin.value_usd(q)?),
        }
    }
}
```

**File:** packages/rujira-rs/src/oracle.rs (L55-62)
```rust
impl OracleValue for Coin {
    fn value_usd(&self, q: QuerierWrapper) -> Result<Decimal, OracleError> {
        Ok(SecuredAsset::from_denom(&self.denom)?
            .to_layer_1()
            .oracle_price(q)?
            .checked_mul(Decimal::from_ratio(self.amount, Uint128::one()))?)
    }
}
```

**File:** packages/rujira-rs/src/query/oracle_price.rs (L39-41)
```rust
            }
            None => Err(TryFromOraclePriceError::NotFound {}),
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L105-108)
```rust
            ensure_eq!(info.sender, ca, ContractError::Unauthorized {});
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
