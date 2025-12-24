# Audit Report

## Title
Delegate Share Accounting Corruption Through Non-Delegate Repayment

## Summary
Borrowers who take loans with delegate attribution can corrupt the protocol's delegate share accounting by repaying without specifying the delegate. This creates a permanent inconsistency where `DELEGATE_SHARES` exceeds `borrower.shares`, violating the fundamental invariant that delegate shares must always be a subset of total borrower shares.

## Finding Description

The `rujira-ghost-vault` contract allows borrowers to borrow funds on behalf of specific delegates, tracking this attribution in the `DELEGATE_SHARES` storage map. [1](#0-0) 

When borrowing with a delegate, the system updates both `DELEGATE_SHARES` and the borrower's total shares: [2](#0-1) 

However, the repayment logic contains a critical flaw. When repaying without specifying a delegate, the system only reduces `borrower.shares` without updating any `DELEGATE_SHARES` entries: [3](#0-2) 

The `borrower.repay()` function called when `delegate` is `None` only modifies the total shares: [4](#0-3) 

**Attack Scenario:**
1. Borrower borrows 1000 shares with delegate Alice → `DELEGATE_SHARES[(borrower, Alice)] = 1000`, `borrower.shares = 1000`
2. Borrower repays 600 shares without specifying delegate → `borrower.shares = 400`, but `DELEGATE_SHARES[(borrower, Alice)]` remains `1000`
3. Result: `DELEGATE_SHARES[(borrower, Alice)] = 1000 > borrower.shares = 400` ✗

This violates the critical invariant that the sum of all delegate shares for a borrower must always be ≤ borrower.shares. The delegate query now returns logically impossible data: [5](#0-4) 

## Impact Explanation

**High Severity** - This vulnerability causes permanent state corruption with the following impacts:

1. **Broken Accounting Invariant**: The fundamental invariant `Σ(delegate_shares) ≤ borrower.shares` is violated, corrupting the protocol's debt attribution system.

2. **Orphaned Delegate Shares**: Delegate shares can persist in storage even after the borrower has fully repaid their debt, creating ghost entries that misrepresent the protocol's state.

3. **Misleading Protocol Queries**: The `QueryMsg::Delegate` endpoint returns logically inconsistent data showing delegate debt exceeding total borrower debt, breaking integrations and monitoring systems.

4. **Irreversible State Corruption**: Once corrupted, the delegate share accounting cannot be corrected without contract migration, as there's no mechanism to reconcile orphaned shares.

5. **Potential Downstream Effects**: While this doesn't directly steal funds, broken accounting in DeFi lending protocols can lead to cascading failures in liquidation calculations, collateral assessments, and credit limit determinations if the system expands to use delegate shares for risk management.

## Likelihood Explanation

**High Likelihood** - This vulnerability is trivially exploitable:

- **No Special Permissions Required**: Any whitelisted borrower can trigger this by simply repaying without specifying the delegate parameter.
- **No Economic Cost**: The attacker doesn't lose anything by corrupting the accounting.
- **Happens During Normal Operations**: Users might naturally repay without specifying delegates, unintentionally corrupting the system.
- **No Detection Mechanisms**: The protocol has no validation to prevent or detect this inconsistency.
- **Permanent Effect**: Once triggered, the corruption is permanent until contract migration.

## Recommendation

Add validation to prevent repaying without a delegate when delegate shares exist:

```rust
MarketMsg::Repay { delegate } => {
    let amount = must_pay(&info, config.denom.as_str())?;
    let delegate_address = delegate
        .clone()
        .map(|d| deps.api.addr_validate(&d))
        .transpose()?;

    // NEW: Validate delegate repayment consistency
    if delegate_address.is_none() {
        // Check if any delegate shares exist for this borrower
        let has_delegate_shares = /* iterate DELEGATE_SHARES to check */;
        if has_delegate_shares {
            return Err(ContractError::MustSpecifyDelegate {});
        }
    }

    let borrower_shares = match delegate_address.as_ref() {
        Some(d) => borrower.delegate_shares(deps.storage, d.clone()),
        None => borrower.shares,
    };
    // ... rest of repay logic
}
```

Alternatively, when repaying without a delegate, proportionally reduce all delegate shares:

```rust
None => {
    // Proportionally reduce all delegate shares
    borrower.repay_proportional(deps.storage, shares)?;
}
```

## Proof of Concept

```rust
#[test]
fn test_delegate_share_corruption() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let borrower = app.api().addr_make("borrower");
    let delegate = app.api().addr_make("alice");

    // Setup: Initialize balances
    app.init_modules(|router, _, storage| {
        router.bank.init_balance(storage, &owner, coins(10_000, "btc")).unwrap();
        router.bank.init_balance(storage, &borrower, coins(10_000, "btc")).unwrap();
    });

    // Deploy vault
    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    let contract = app.instantiate_contract(
        code_id, owner.clone(),
        &InstantiateMsg {
            denom: "btc".to_string(),
            receipt: TokenMetadata { /* ... */ },
            interest: Interest { /* ... */ },
            fee: Decimal::zero(),
            fee_address: owner.to_string(),
        },
        &[], "vault", None,
    ).unwrap();

    // Owner deposits liquidity
    app.execute_contract(owner.clone(), contract.clone(), 
        &ExecuteMsg::Deposit { callback: None }, 
        &coins(5_000, "btc")
    ).unwrap();

    // Whitelist borrower
    app.wasm_sudo(contract.clone(), &SudoMsg::SetBorrower {
        contract: borrower.to_string(),
        limit: Uint128::from(2_000u128),
    }).unwrap();

    // Step 1: Borrow 1000 shares WITH delegate Alice
    app.execute_contract(borrower.clone(), contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Borrow {
            amount: Uint128::from(1_000u128),
            callback: None,
            delegate: Some(delegate.to_string()),
        }), &[]
    ).unwrap();

    // Verify initial state
    let delegate_resp: DelegateResponse = app.wrap().query_wasm_smart(
        contract.clone(),
        &QueryMsg::Delegate { 
            borrower: borrower.to_string(), 
            addr: delegate.to_string() 
        },
    ).unwrap();
    assert_eq!(delegate_resp.shares, Uint128::from(1_000u128));
    assert_eq!(delegate_resp.borrower.shares, Uint128::from(1_000u128));

    // Step 2: Repay 600 shares WITHOUT specifying delegate
    app.execute_contract(borrower.clone(), contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        &coins(600, "btc")
    ).unwrap();

    // Step 3: Verify accounting corruption
    let delegate_resp: DelegateResponse = app.wrap().query_wasm_smart(
        contract.clone(),
        &QueryMsg::Delegate { 
            borrower: borrower.to_string(), 
            addr: delegate.to_string() 
        },
    ).unwrap();
    
    // BUG: Delegate shares (1000) exceeds total borrower shares (400)
    assert_eq!(delegate_resp.shares, Uint128::from(1_000u128)); 
    assert_eq!(delegate_resp.borrower.shares, Uint128::from(400u128));
    assert!(delegate_resp.shares > delegate_resp.borrower.shares); // INVARIANT VIOLATED!
}
```

**Notes:**
While the security question asked about mid-execution failures, CosmWasm's atomic transaction model prevents such inconsistencies. However, this analysis uncovered a more critical vulnerability: delegate shares become inconsistent through successful repayment operations when the delegate parameter is omitted, permanently corrupting the protocol's debt attribution accounting.

### Citations

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L14-15)
```rust
// Delegated shares for a borrower
static DELEGATE_SHARES: Map<(Addr, Addr), Uint128> = Map::new("delegates");
```

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L43-56)
```rust
    pub fn delegate_borrow(
        &mut self,
        storage: &mut dyn Storage,
        delegate: Addr,
        pool: &SharePool,
        shares: Uint128,
    ) -> Result<(), ContractError> {
        DELEGATE_SHARES.update(
            storage,
            (self.addr.clone(), delegate),
            |v| -> Result<Uint128, ContractError> { Ok(v.unwrap_or_default().add(shares)) },
        )?;
        self.borrow(storage, pool, shares)
    }
```

**File:** contracts/rujira-ghost-vault/src/borrowers.rs (L71-80)
```rust
    pub fn repay(
        &mut self,
        storage: &mut dyn Storage,
        shares: Uint128,
    ) -> Result<Uint128, ContractError> {
        let repaid = min(shares, self.shares);
        self.shares -= repaid;
        self.save(storage)?;
        Ok(shares.sub(repaid))
    }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L162-181)
```rust
        MarketMsg::Repay { delegate } => {
            let amount = must_pay(&info, config.denom.as_str())?;
            let delegate_address = delegate
                .clone()
                .map(|d| deps.api.addr_validate(&d))
                .transpose()?;

            let borrower_shares = match delegate_address.as_ref() {
                Some(d) => borrower.delegate_shares(deps.storage, d.clone()),
                None => borrower.shares,
            };
            let borrower_debt = state.debt_pool.ownership(borrower_shares);
            let repay_amount = min(amount, borrower_debt);

            let shares = state.repay(repay_amount)?;

            match delegate_address.clone() {
                Some(d) => borrower.delegate_repay(deps.storage, d, shares),
                None => borrower.repay(deps.storage, shares),
            }?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L266-287)
```rust
        QueryMsg::Delegate { borrower, addr } => {
            let borrower = Borrower::load(deps.storage, deps.api.addr_validate(&borrower)?)?;
            let delegate = borrower.delegate_shares(deps.storage, deps.api.addr_validate(&addr)?);
            let current = state.debt_pool.ownership(borrower.shares);

            Ok(to_json_binary(&DelegateResponse {
                borrower: BorrowerResponse {
                    addr: borrower.addr.to_string(),
                    denom: config.denom,
                    limit: borrower.limit,
                    current,
                    shares: borrower.shares,
                    available: min(
                        borrower.limit.checked_sub(current).unwrap_or_default(),
                        state.deposit_pool.size() - state.debt_pool.size(),
                    ),
                },
                addr,
                current: state.debt_pool.ownership(delegate),
                shares: delegate,
            })?)
        }
```
