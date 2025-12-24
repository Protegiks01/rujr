# Audit Report

## Title
Denial of Service: Single Account Failure Prevents Querying All Accounts by Owner

## Summary
The `by_owner()` function uses Rust's `.collect()` on an iterator of `Result` types, which short-circuits on the first error. If any single account fails during the `to_credit_account()` conversion (due to oracle query failures, vault query errors, or network issues), the entire query fails, preventing users from viewing any of their accounts.

## Finding Description
The vulnerability exists in the `by_owner()` function which queries all accounts owned by a specific address. [1](#0-0) 

The function maps each stored account through `to_credit_account()` and collects the results. Due to Rust's `.collect()` behavior on iterators of `Result<T, E>`, if ANY single account conversion fails, the entire collection operation short-circuits and returns that error.

The `to_credit_account()` function performs multiple failable operations for each account: [2](#0-1) 

Each account conversion performs:
- Balance queries for configured collateral denoms (line 301)
- Multiple oracle queries for USD valuations (lines 302, 306, 314)
- Vault delegate queries (line 313)
- Collateral ratio adjustments (line 307)

If any of these operations fail for a single account (e.g., oracle timeout, network error, vault query failure), the entire `by_owner()` call fails.

This issue manifests when users query their accounts via `QueryMsg::Accounts`: [3](#0-2) 

While individual accounts can still be queried using `QueryMsg::Account(addr)`, users must know the specific account addresses to use this workaround. [4](#0-3) 

## Impact Explanation
**Medium Severity** - This is a Denial of Service vulnerability affecting core protocol functionality:

1. **Complete Query Failure**: Users with multiple accounts cannot view ANY accounts if one fails, not just the failed account
2. **Position Monitoring Disruption**: Users rely on account queries to monitor collateral ratios and debt levels. Without this visibility, they cannot take preventive action against liquidation
3. **Potential Financial Loss**: Inability to monitor positions could lead to unexpected liquidations if users cannot adjust collateral or repay debt in time
4. **Degraded User Experience**: Users must resort to querying accounts individually by address, requiring external tracking of account addresses

This qualifies as Medium severity under the stated criteria: "DoS vulnerabilities affecting core functionality" and "State inconsistencies requiring manual intervention."

## Likelihood Explanation
**High Likelihood** - This issue occurs naturally under common failure scenarios:

1. **Oracle Service Disruptions**: THORChain oracle queries can fail due to rate limiting, network congestion, or temporary service unavailability. Oracle queries occur at lines 302, 306, and 314 of `to_credit_account()`
2. **Network Issues**: Transient network problems can cause any of the external queries (balance, vault, oracle) to fail
3. **Vault Query Failures**: If any vault has issues or is being upgraded, the delegate query at line 313 can fail
4. **No Attacker Required**: This bug manifests naturally without malicious action, making it more likely than attack-dependent vulnerabilities

In production DeFi systems, oracle and network failures occur regularly, making this a realistic and recurring issue.

## Recommendation
Implement graceful degradation by collecting successful accounts and logging errors for failed ones, rather than failing the entire query:

```rust
pub fn by_owner(
    deps: Deps,
    config: &Config,
    contract: Addr,
    owner: &Addr,
    tag: Option<String>,
) -> Result<Vec<Self>, ContractError> {
    match tag {
        Some(tag) => Self::store().idx.owner_tag.prefix((owner.clone(), tag)),
        None => Self::store().idx.owner.prefix(owner.clone()),
    }
    .range(deps.storage, None, None, Order::Descending)
    .filter_map(|x| match x {
        Ok((_, stored)) => stored.to_credit_account(deps, &contract, config).ok(),
        Err(_) => None,
    })
    .collect::<Vec<Self>>()
    .into()
}
```

This approach:
- Returns all successfully loaded accounts
- Silently skips accounts that fail to load
- Allows users to view healthy accounts even when one has issues
- Maintains backward compatibility by returning `Ok(Vec<Self>)`

Alternatively, introduce a new query endpoint that returns partial results with error information:

```rust
pub struct AccountsWithErrors {
    pub accounts: Vec<CreditAccount>,
    pub errors: Vec<(Addr, String)>,
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{coin, Addr};

    #[test]
    fn test_by_owner_fails_on_single_account_error() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Setup: Create config with collateral ratios
        let config = Config {
            collateral_ratios: vec![
                ("btc-btc".to_string(), Decimal::percent(90)),
            ].into_iter().collect(),
            // ... other config fields
        };
        
        // Create two accounts for the same owner
        let owner = Addr::unchecked("owner1");
        let account1 = Addr::unchecked("account1");
        let account2 = Addr::unchecked("account2"); // This one will fail
        
        // Store accounts
        CreditAccount::store().save(
            deps.as_mut().storage,
            account1.clone(),
            &Stored {
                owner: owner.clone(),
                account: account1.clone(),
                tag: "".to_string(),
                liquidation_preferences: Default::default(),
            },
        ).unwrap();
        
        CreditAccount::store().save(
            deps.as_mut().storage,
            account2.clone(),
            &Stored {
                owner: owner.clone(),
                account: account2.clone(), // This account doesn't exist, will cause query failure
                tag: "".to_string(),
                liquidation_preferences: Default::default(),
            },
        ).unwrap();
        
        // Attempt to query all accounts by owner
        // This will fail because account2's balance query will fail
        let result = CreditAccount::by_owner(
            deps.as_ref(),
            &config,
            env.contract.address.clone(),
            &owner,
            None,
        );
        
        // Assert: The entire query fails, user cannot see account1 either
        assert!(result.is_err());
        
        // Even though account1 might be perfectly valid, user cannot access it
        // through by_owner() due to account2's failure
    }
}
```

**Note**: This is a conceptual PoC demonstrating the issue. The actual test would require full mock setup of the CosmWasm environment with oracle queries and vault contracts, which is complex to reproduce outside the existing test framework. The key point is that the `.collect()` operation on line 119 of `by_owner()` will short-circuit on the first `Err` returned from `to_credit_account()`, causing the entire query to fail.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L103-120)
```rust
    pub fn by_owner(
        deps: Deps,
        config: &Config,
        contract: Addr,
        owner: &Addr,
        tag: Option<String>,
    ) -> Result<Vec<Self>, ContractError> {
        match tag {
            Some(tag) => Self::store().idx.owner_tag.prefix((owner.clone(), tag)),
            None => Self::store().idx.owner.prefix(owner.clone()),
        }
        .range(deps.storage, None, None, Order::Descending)
        .map::<Result<Self, ContractError>, _>(|x| match x {
            Ok((_, stored)) => stored.to_credit_account(deps, &contract, config),
            Err(err) => Err(ContractError::Std(err)),
        })
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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L415-426)
```rust
        QueryMsg::Accounts { owner, tag } => Ok(to_json_binary(&AccountsResponse {
            accounts: CreditAccount::by_owner(
                deps,
                &config,
                env.contract.address,
                &deps.api.addr_validate(&owner)?,
                tag,
            )?
            .iter()
            .map(|x| AccountResponse::from(x.clone()))
            .collect(),
        })?),
```
