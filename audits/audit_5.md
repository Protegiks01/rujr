# Audit Report

## Title
Registry Admin Key Compromise Enables Total Protocol Drain Due to Lack of Defense-in-Depth Safeguards

## Summary
The `rujira-account` contract's sudo entrypoint accepts any `CosmosMsg` without validation, and the protocol lacks defense-in-depth mechanisms (timelocks, migration restrictions, or additional access controls) to protect against registry admin key compromise. If the registry admin key is compromised, an attacker can migrate the registry to malicious code and drain all accounts simultaneously.

## Finding Description

The Rujira protocol uses a three-tier access control model where the registry (`rujira-ghost-credit`) is set as the admin of all account contracts (`rujira-account`). The account contract's sudo entrypoint has zero validation: [1](#0-0) 

When accounts are created, the registry contract address is set as their admin: [2](#0-1) 

The registry passes itself (`ca = env.contract.address`) as the admin parameter, which propagates through: [3](#0-2) 

In CosmWasm, the contract admin can call `MsgMigrateContract` to upgrade the contract to new code. If the registry admin key is compromised:

1. **Attacker migrates registry**: Uses `MsgMigrateContract` to replace the registry with malicious code
2. **Enumerates all accounts**: Malicious code queries all accounts using the existing `list` function [4](#0-3) 
3. **Constructs drain messages**: Uses the existing `Account::sudo()` helper to create `MsgSudoContract` messages [5](#0-4) 
4. **Drains all accounts**: Each sudo call contains `BankMsg::Send` to transfer all collateral to the attacker

Users deposit collateral directly to account addresses, and these funds are held by the account contract: [6](#0-5) 

**Broken Invariants:**
- **Admin-Only Accounts** (Invariant #7): While technically the registry remains the admin, the lack of additional safeguards means a compromised admin key provides unrestricted access
- **Owner-Gated Accounts** (Invariant #1): Account ownership becomes meaningless when the admin can directly drain funds

**Missing Safeguards:**
- No timelock delay on migrations
- No whitelist of approved code IDs for migration
- No multi-signature requirement for sensitive operations
- No emergency pause mechanism
- No user ability to change account admin
- No validation whatsoever in account's sudo entrypoint
- No migration restrictions in the registry's migrate function [7](#0-6) 

## Impact Explanation

**Critical Severity** - This vulnerability results in:
- **Total protocol drain**: All user collateral across all accounts can be stolen simultaneously
- **No recovery mechanism**: Once funds are transferred out, they cannot be recovered
- **Systemic failure**: The entire protocol becomes compromised with a single key breach

The impact is systemic because:
1. One compromised key affects ALL accounts (not just specific users)
2. Attack can be executed atomically (all accounts drained in one transaction sequence)
3. No warning or detection period (instant execution after migration)
4. Affects all asset types held as collateral

## Likelihood Explanation

While key compromise requires a security breach of the admin multisig, the likelihood should be assessed as **feasible** because:

1. **Single point of failure**: One compromised key (even from a multisig) combined with compromised threshold members leads to total loss
2. **Permanent exposure**: The vulnerability exists for the lifetime of the protocol
3. **High-value target**: As TVL grows, the incentive for sophisticated attackers increases
4. **No detection/response time**: Unlike gradual exploits, a migration can be executed immediately

**Note**: This finding is valid specifically because the security question explicitly asks about key compromise scenarios. Per the protocol's trust model, this would normally be out of scope, but defense-in-depth analysis is requested here.

## Recommendation

Implement multiple layers of defense:

1. **Timelock on migrations**: Add a mandatory delay (e.g., 48-72 hours) between migration proposal and execution:
```rust
pub struct MigrationProposal {
    pub new_code_id: u64,
    pub proposed_at: Timestamp,
    pub executed: bool,
}

const MIGRATION_DELAY: u64 = 259200; // 72 hours in seconds
```

2. **Code ID whitelist**: Restrict migrations to pre-approved code IDs:
```rust
pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    let config = Config::load(deps.storage)?;
    ensure!(
        config.approved_code_ids.contains(&msg.new_code_id),
        ContractError::UnauthorizedCodeId {}
    );
    // ... rest of migration logic
}
```

3. **Add validation to account sudo entrypoint**: Restrict the types of messages that can be executed:
```rust
pub fn sudo(deps: DepsMut, env: Env, msg: CosmosMsg) -> Result<Response, ContractError> {
    // Only allow specific message types from registry
    match msg {
        CosmosMsg::Bank(BankMsg::Send { to_address, .. }) => {
            // Validate destination is not arbitrary
            let config = Config::load(deps.storage)?;
            ensure!(
                is_whitelisted_destination(&to_address, &config),
                ContractError::UnauthorizedDestination {}
            );
        },
        CosmosMsg::Wasm(WasmMsg::Execute { .. }) => {
            // Allow contract executions
        },
        _ => return Err(ContractError::UnauthorizedSudoMessage {}),
    }
    Ok(Response::default().add_message(msg))
}
```

4. **User-controlled emergency withdrawal**: Allow users to withdraw to pre-set addresses even if registry is compromised (requires protocol redesign)

5. **Multi-tier admin structure**: Separate admin roles for different operations (migration, config updates, emergency actions)

## Proof of Concept

This PoC demonstrates the vulnerability flow (conceptual - would require full test environment):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compromised_admin_drains_all_accounts() {
        let mut app = App::default();
        
        // 1. Setup: Deploy registry and create user accounts with collateral
        let registry_admin = Addr::unchecked("admin");
        let attacker = Addr::unchecked("attacker");
        
        // Deploy registry with admin as admin
        let registry = deploy_registry(&mut app, &registry_admin);
        
        // Users create accounts and deposit collateral
        let user1 = create_account_with_collateral(&mut app, &registry, Uint128::new(1000000));
        let user2 = create_account_with_collateral(&mut app, &registry, Uint128::new(2000000));
        let user3 = create_account_with_collateral(&mut app, &registry, Uint128::new(5000000));
        
        // Total TVL = 8,000,000
        
        // 2. Admin key is compromised - attacker deploys malicious registry code
        let malicious_code_id = app.store_code(malicious_registry_contract());
        
        // 3. Attacker migrates registry to malicious code
        app.migrate_contract(
            attacker.clone(), // Compromised admin key
            registry.clone(),
            &MigrateMsg {},
            malicious_code_id,
        ).unwrap();
        
        // 4. Malicious registry enumerates all accounts
        let accounts: Vec<Addr> = app.wrap().query_wasm_smart(
            registry.clone(),
            &QueryMsg::AllAccounts { cursor: None, limit: None },
        ).unwrap();
        
        // 5. For each account, construct sudo message to drain funds
        for account in accounts {
            let balance = app.wrap().query_all_balances(&account).unwrap();
            
            // Malicious registry calls account.sudo(BankMsg::Send) 
            app.execute_contract(
                registry.clone(), // Registry itself executes (it's the admin)
                account.clone(),
                &SudoMsg::DrainAccount {
                    destination: attacker.clone(),
                    amount: balance,
                },
                &[],
            ).unwrap();
        }
        
        // 6. Verify attacker received all funds
        let attacker_balance = app.wrap().query_all_balances(&attacker).unwrap();
        assert_eq!(attacker_balance[0].amount, Uint128::new(8000000));
        
        // 7. Verify all accounts are empty
        assert_eq!(app.wrap().query_all_balances(&user1).unwrap(), vec![]);
        assert_eq!(app.wrap().query_all_balances(&user2).unwrap(), vec![]);
        assert_eq!(app.wrap().query_all_balances(&user3).unwrap(), vec![]);
    }
}

// Malicious registry that drains accounts
fn malicious_registry_contract() -> Box<dyn Contract<Empty>> {
    Box::new(ContractWrapper::new(
        |deps, env, info, msg: ExecuteMsg| -> Result<Response, ContractError> {
            match msg {
                ExecuteMsg::DrainAll { attacker } => {
                    // Query all accounts
                    let accounts = CreditAccount::list(deps.as_ref(), /* ... */)?;
                    
                    let mut messages = vec![];
                    for account in accounts {
                        // Get account balance
                        let balance = deps.querier.query_all_balances(&account.id())?;
                        
                        // Construct sudo message to send funds to attacker
                        messages.push(account.account.send(&attacker, balance)?);
                    }
                    
                    Ok(Response::new().add_messages(messages))
                }
                _ => Err(ContractError::Unauthorized {})
            }
        },
        // ... instantiate, query, sudo handlers
    ))
}
```

**Notes:**

1. This vulnerability is explicitly in scope because the security question asks about admin key compromise scenarios

2. The core issue is architectural: placing complete trust in a single admin key without defense-in-depth mechanisms violates security best practices for high-value DeFi protocols

3. While the Rujira Deployer Multisig is trusted under normal operations, defense-in-depth principles require additional safeguards against key compromise scenarios

4. The lack of any validation in the account's sudo entrypoint combined with no migration restrictions creates a critical single point of failure

### Citations

**File:** contracts/rujira-account/src/contract.rs (L32-35)
```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(_deps: DepsMut, _env: Env, msg: CosmosMsg) -> Result<Response, ContractError> {
    Ok(Response::default().add_message(msg))
}
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L57-66)
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
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L457-461)
```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: ()) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::default())
}
```

**File:** contracts/rujira-ghost-credit/src/account.rs (L74-98)
```rust
    pub fn create(
        deps: Deps,
        code_id: u64,
        admin: Addr,
        owner: Addr,
        label: String,
        tag: String,
        salt: Binary,
    ) -> Result<(Self, WasmMsg), ContractError> {
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update(salt.as_slice());

        let mut salt = salt.to_vec();
        salt.append(&mut deps.api.addr_canonicalize(owner.as_ref())?.to_vec());
        let (account, msg) = Account::create(
            deps,
            admin,
            code_id,
            format!("ghost-credit/{label}"),
            Binary::from(hasher.finalize().to_vec()),
        )?;
        let acc = Self::new(owner, account, tag);
        Ok((acc, msg))
    }
```

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

**File:** packages/rujira-rs/src/interfaces/account.rs (L56-73)
```rust
    pub fn sudo(&self, msg: &CosmosMsg) -> StdResult<CosmosMsg> {
        Ok(CosmosMsg::Any(AnyMsg {
            type_url: "/cosmwasm.wasm.v1.MsgSudoContract".to_string(),
            value: Anybuf::new()
                .append_string(1, &self.admin)
                .append_string(2, &self.addr)
                .append_bytes(3, to_json_binary(msg)?)
                .into_vec()
                .into(),
        }))
    }

    pub fn send(&self, to_address: impl Into<String>, amount: Vec<Coin>) -> StdResult<CosmosMsg> {
        self.sudo(&CosmosMsg::Bank(BankMsg::Send {
            to_address: to_address.into(),
            amount,
        }))
    }
```

**File:** contracts/rujira-ghost-credit/README.md (L10-13)
```markdown

## Collateralisation

Funding your Account is simply a case of sending it funds. Any tokens that are held by the contract are considered collateral by the Registry. They can be withdrawn via the Registry.
```
