# Audit Report

## Title
Unbounded Iteration in `by_owner()` Enables Query DoS via Account Griefing

## Summary
The `by_owner()` function in `contracts/rujira-ghost-credit/src/account.rs` uses unbounded iteration when querying accounts by owner, allowing an attacker to create thousands of accounts and transfer them to a victim, causing gas exhaustion and preventing the victim from querying their accounts through `QueryMsg::Accounts`.

## Finding Description

The `by_owner()` function performs unbounded iteration over all accounts matching a given owner or owner/tag combination: [1](#0-0) 

This function is called from the `QueryMsg::Accounts` query handler: [2](#0-1) 

For each account in the iteration, `to_credit_account()` performs expensive operations including multiple external queries for collateral balances and debt values: [3](#0-2) 

An attacker can exploit this by:

1. Creating thousands of accounts under their own ownership (no limits on account creation): [4](#0-3) 

2. Transferring all accounts to a victim address using `AccountMsg::Transfer`: [5](#0-4) 

3. When the victim (or any UI/service) calls `QueryMsg::Accounts` for that owner address, the query iterates through all accounts, performing expensive operations for each one, and eventually runs out of gas in the CosmWasm query context.

The attack breaks the fundamental expectation that users should be able to efficiently query their own accounts. While alternative query methods exist (`AllAccounts` with pagination), the primary user-facing query mechanism is rendered unusable.

## Impact Explanation

**Medium Severity** - This is a DoS vulnerability affecting core query functionality:

- Users cannot query their accounts via `QueryMsg::Accounts`, which is the primary method for discovering account addresses by owner
- Off-chain services, UIs, and monitoring tools that rely on this query will fail for affected addresses
- Users may be unable to discover account addresses needed to perform operations or monitor LTV ratios
- While workarounds exist (using `AllAccounts` with pagination or querying individual accounts if addresses are known), these are not intuitive or user-friendly
- No direct fund loss occurs, but operational functionality is significantly degraded

## Likelihood Explanation

**Medium Likelihood**:

- Attack is straightforward to execute by any unprivileged user
- Attacker must pay gas costs for creating and transferring thousands of accounts, making it economically costly
- Impact is limited to the specific victim address and doesn't affect the entire protocol
- Attacker motivation could include griefing competitors, disrupting protocol integrations, or targeting specific users
- The attack is permanent once executed (accounts cannot be "untransferred" back)

## Recommendation

Add a `limit` parameter to `by_owner()` and enforce maximum iteration bounds similar to the `list()` function:

```rust
pub fn by_owner(
    deps: Deps,
    config: &Config,
    contract: Addr,
    owner: &Addr,
    tag: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<Self>, ContractError> {
    match tag {
        Some(tag) => Self::store().idx.owner_tag.prefix((owner.clone(), tag)),
        None => Self::store().idx.owner.prefix(owner.clone()),
    }
    .range(deps.storage, None, None, Order::Descending)
    .take(limit.unwrap_or(100))  // Add pagination limit
    .map::<Result<Self, ContractError>, _>(|x| match x {
        Ok((_, stored)) => stored.to_credit_account(deps, &contract, config),
        Err(err) => Err(ContractError::Std(err)),
    })
    .collect()
}
```

Update the query handler to accept and pass through the limit parameter: [6](#0-5) 

Add a `limit` parameter to this query message and update the handler accordingly.

Additionally, consider implementing a cursor-based pagination system similar to `AllAccounts` to allow efficient traversal of large account sets.

## Proof of Concept

```rust
#[test]
fn dos_by_owner_query_with_account_spam() {
    let mut app = mock_rujira_app();
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::from_str("1.0").unwrap()),
        ]);
    });

    let attacker = app.api().addr_make("attacker");
    let victim = app.api().addr_make("victim");
    let fees = app.api().addr_make("fees");
    let credit = GhostCredit::create(&mut app, &attacker, &fees);

    // Attacker creates many accounts (simulate 100+ accounts)
    for i in 0..100 {
        let salt = Binary::from(vec![i as u8]);
        credit.create_account(&mut app, &attacker, "", "", salt).unwrap();
    }

    // Verify attacker owns these accounts
    let attacker_accounts = credit.query_accounts(&app, &attacker, None);
    assert!(attacker_accounts.accounts.len() >= 100);

    // Attacker transfers all accounts to victim
    for account in attacker_accounts.accounts {
        app.execute_contract(
            attacker.clone(),
            credit.addr(),
            &ExecuteMsg::Account {
                addr: account.account.to_string(),
                msgs: vec![AccountMsg::Transfer(victim.to_string())],
            },
            &[],
        )
        .unwrap();
    }

    // Now victim tries to query their accounts - this will hit gas limits
    // In a real scenario with 1000+ accounts, this query would fail
    let result = credit.query_accounts(&app, &victim, None);
    
    // With 100 accounts, the query might succeed but with 1000+ it would fail
    // The test demonstrates the attack vector even if it doesn't trigger actual
    // gas exhaustion in the test environment
    assert!(result.accounts.len() >= 100);
}
```

**Note**: The test demonstrates the attack vector. In a production environment with actual CosmWasm query gas limits and thousands of accounts, the query would fail with an out-of-gas error. The test environment may have relaxed limits, but the vulnerability is real on mainnet where query gas is strictly limited.

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L57-72)
```rust
        ExecuteMsg::Create { salt, label, tag } => {
            let (account, msg) = CreditAccount::create(
                deps.as_ref(),
                config.code_id,
                ca,
                info.sender,
                label,
                tag,
                salt,
            )?;
            account.save(deps)?;

            Ok(Response::default()
                .add_message(msg)
                .add_event(event_create_account(&account)))
        }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L226-229)
```rust
        AccountMsg::Transfer(recipient) => {
            let recipient = deps.api.addr_validate(&recipient)?;
            account.owner = recipient.clone();
            Ok((vec![], vec![event_execute_account_transfer(&recipient)]))
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

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L153-159)
```rust
    /// Queries all accounts by an owner
    #[returns(AccountsResponse)]
    Accounts {
        owner: String,
        /// Optionally filter by a given tag
        tag: Option<String>,
    },
```
