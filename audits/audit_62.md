# Audit Report

## Title
Unbounded Query Limit Enables DoS Attack on AllAccounts Query Endpoint

## Summary

The `QueryMsg::AllAccounts` handler lacks an upper bound validation on the `limit` parameter, allowing attackers to request an arbitrarily large number of accounts in a single query. Combined with expensive per-account operations (multiple balance and vault queries), this creates a severe DoS vulnerability that can overload RPC nodes and prevent critical protocol operations like liquidations. [1](#0-0) 

## Finding Description

The vulnerability exists in the `CreditAccount::list()` function where the limit parameter uses `.unwrap_or(100)` to set a default value when `None` is provided, but fails to enforce a maximum cap when a value is explicitly provided. [2](#0-1) 

The QueryMsg definition accepts an unbounded `Option<usize>` for the limit parameter: [3](#0-2) 

When processing each account, the `to_credit_account()` function performs expensive operations for EVERY configured collateral type and vault: [4](#0-3) 

**Attack Path:**
1. Attacker identifies the AllAccounts query endpoint
2. Attacker calls the query with `limit: Some(10000)` or higher
3. The contract processes each account by:
   - Querying balance for each collateral denom configured (line 301)
   - Calling oracle for USD value (lines 302, 306)
   - Querying each vault's delegate info (line 313)
   - Calling oracle for debt USD value (line 314)
4. With C collateral types and V vaults: `limit * (C * 3 + V * 2)` total operations
5. Example: 10,000 accounts × (5 collaterals × 3 + 5 vaults × 2) = 250,000 operations
6. Attacker repeats the query to sustain DoS

The query handler passes the limit directly without validation: [5](#0-4) 

## Impact Explanation

This is a **Medium Severity** DoS vulnerability affecting core protocol functionality:

1. **RPC Node Overload**: Queries with large limits (10,000+ accounts) trigger hundreds of thousands of sub-queries, overwhelming node resources
2. **Liquidation Disruption**: Liquidators rely on querying accounts to identify liquidation targets. If the query endpoint is unresponsive, liquidations fail, risking protocol insolvency
3. **User Experience Degradation**: Legitimate users cannot access their account information
4. **Memory Exhaustion**: Collecting tens of thousands of `AccountResponse` objects into a vector can cause OOM errors
5. **No Rate Limiting**: Queries typically lack the same rate limiting as transactions, making repeated attacks trivial

Even with the default limit of 100, repeated queries cause 100 × ~15 = ~1,500 operations per query, which when spammed can still cause degradation. However, the lack of a maximum bound makes the attack orders of magnitude worse.

## Likelihood Explanation

**Likelihood: HIGH**

- **No Authentication Required**: Any external actor can call the query endpoint
- **Zero Cost Attack**: Queries are free to execute (no transaction fees)
- **Trivial Execution**: Single query call with high limit parameter
- **No Mitigation**: No rate limiting or maximum bound in the contract code
- **Clear Motivation**: Competitors, griefers, or attackers seeking to disrupt liquidations could exploit this

The comment on line 161 indicates the developers intended 100 as a pagination limit ("Pages through all accounts, 100 at a time"), but failed to enforce it as a maximum: [6](#0-5) 

## Recommendation

Enforce a maximum limit cap of 100 by modifying the `list` function:

```rust
pub fn list(
    deps: Deps,
    config: &Config,
    contract: &Addr,
    cursor: Option<Addr>,
    limit: Option<usize>,
) -> Result<Vec<Self>, ContractError> {
    const MAX_LIMIT: usize = 100;
    
    Self::store()
        .range(
            deps.storage,
            cursor.map(Bound::exclusive),
            None,
            Order::Ascending,
        )
        .take(limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT))  // Cap at MAX_LIMIT
        .map(|res| res?.1.to_credit_account(deps, contract, config))
        .collect()
}
```

Additionally, consider implementing query gas metering at the node level or adding explicit validation in the query handler.

## Proof of Concept

```rust
#[cfg(test)]
mod dos_tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coin, Addr, Decimal};
    use crate::mock::GhostCredit;
    use rujira_rs_testing::{mock_rujira_app, RujiraApp};
    use std::str::FromStr;

    #[test]
    fn test_unbounded_limit_dos() {
        let mut app = mock_rujira_app();
        app.init_modules(|router, _, _| {
            router.stargate.with_prices(vec![
                ("USDC", Decimal::from_str("1.0").unwrap()),
                ("BTC", Decimal::from_str("50000.0").unwrap()),
            ]);
        });

        let owner = app.api().addr_make("owner");
        let fees = app.api().addr_make("fees");
        let credit = GhostCredit::create(&mut app, &owner, &fees);
        
        // Setup collateral ratios to make queries expensive
        credit.set_collateral(&mut app, "USDC", "0.9");
        credit.set_collateral(&mut app, "BTC", "0.9");
        credit.set_collateral(&mut app, "ETH", "0.9");
        credit.set_collateral(&mut app, "ATOM", "0.9");
        credit.set_collateral(&mut app, "THOR", "0.9");

        // Create multiple accounts to simulate realistic scenario
        for i in 0..10 {
            let user = app.api().addr_make(&format!("user{}", i));
            app.send_tokens(owner.clone(), user.clone(), &[coin(1000, "USDC")]).unwrap();
            credit.create_account(&mut app, &user, "", "", Binary::from(vec![i]));
        }

        // Normal query with reasonable limit works fine
        let result = app.wrap().query_wasm_smart::<AccountsResponse>(
            credit.addr().clone(),
            &QueryMsg::AllAccounts {
                cursor: None,
                limit: Some(10),
            },
        );
        assert!(result.is_ok());

        // Attack: Query with extremely large limit
        // This would cause 10000 * (5 collaterals * 3 queries + N vaults * 2 queries)
        // Even though we only have 10 accounts, the contract will attempt to process
        // up to 10000 accounts, performing expensive operations on each
        let attack_result = app.wrap().query_wasm_smart::<AccountsResponse>(
            credit.addr().clone(),
            &QueryMsg::AllAccounts {
                cursor: None,
                limit: Some(10000), // Unbounded - should be capped at 100
            },
        );
        
        // The query succeeds (processes all 10 accounts) but demonstrates
        // that there's no protection against requesting 10000+ accounts
        // In a production environment with thousands of accounts, this would
        // cause severe resource exhaustion
        assert!(attack_result.is_ok());
        
        // The vulnerability is that limit can be arbitrarily large
        // With more accounts, this becomes a serious DoS vector
        println!("Vulnerability: No maximum limit enforcement allows DoS via large limit values");
    }
}
```

**Notes**

The vulnerability stems from incomplete implementation of pagination limits. While the default of 100 is reasonable, the absence of a maximum bound allows malicious actors to bypass this protection entirely. The issue is compounded by the expensive per-account operations in `to_credit_account()`, which perform multiple external queries for collateral balances, oracle prices, and vault delegate information. This creates a multiplicative DoS vector where `limit × num_queries_per_account` can easily reach hundreds of thousands of operations in a single query call.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L122-139)
```rust
    pub fn list(
        deps: Deps,
        config: &Config,
        contract: &Addr,
        cursor: Option<Addr>,
        limit: Option<usize>,
    ) -> Result<Vec<Self>, ContractError> {
        Self::store()
            .range(
                deps.storage,
                cursor.map(Bound::exclusive),
                None,
                Order::Ascending,
            )
            .take(limit.unwrap_or(100))
            .map(|res| res?.1.to_credit_account(deps, contract, config))
            .collect()
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

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L161-168)
```rust
    /// Pages through all accounts, 100 at a time
    #[returns(AccountsResponse)]
    AllAccounts {
        /// Address of the Credit Account
        cursor: Option<String>,
        /// Number of accounts to return
        limit: Option<usize>,
    },
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L428-439)
```rust
        QueryMsg::AllAccounts { cursor, limit } => Ok(to_json_binary(&AccountsResponse {
            accounts: CreditAccount::list(
                deps,
                &config,
                &env.contract.address,
                cursor.map(|x| deps.api.addr_validate(&x)).transpose()?,
                limit,
            )?
            .iter()
            .map(|x| AccountResponse::from(x.clone()))
            .collect(),
        })?),
```
