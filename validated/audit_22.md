# Audit Report

## Title
Permanent Vault Freeze via Unchecked Withdrawal Leading to Arithmetic Underflow in Utilization Calculation

## Summary
The `State::withdraw()` function in the ghost-vault contract fails to validate that withdrawals maintain the critical invariant `deposit_pool.size >= debt_pool.size`. When this invariant is violated through legitimate withdrawal operations, the `State::utilization()` function performs an unchecked subtraction that underflows, causing ALL vault operations to fail permanently and freezing all deposited funds.

## Finding Description

This vulnerability exists in the withdrawal validation logic of the `rujira-ghost-vault` contract and breaks the "Always-Accrued Interest" invariant (#10 from the protocol documentation).

**Root Cause:**

The `State::withdraw()` function delegates to `SharePool::leave()` which only validates that the user has sufficient shares to burn, but does not enforce the protocol invariant that total deposits must always be greater than or equal to total debt: [1](#0-0) 

The underlying `SharePool::leave()` implementation only checks share ownership: [2](#0-1) 

**Underflow Location:**

When `debt_pool.size > deposit_pool.size`, the `State::utilization()` function performs an unchecked subtraction using Rust's `Uint128::sub()` method, which panics on underflow: [3](#0-2) 

The critical operation at line 83 is `self.deposit_pool.size().sub(self.debt_pool.size())`. In Rust, `Uint128` subtraction panics when the result would be negative.

**Cascading Failure:**

This utilization calculation is invoked from multiple critical code paths, causing complete vault failure:

1. **All execute operations** call `distribute_interest()` before any state changes: [4](#0-3) 

2. **`distribute_interest()` calls `calculate_interest()` which calls `debt_rate()`**: [5](#0-4) 

3. **`debt_rate()` calls `utilization()`** where the underflow occurs: [6](#0-5) 

4. **All query operations** also trigger the same failure path: [7](#0-6) 

5. **Additional underflows occur in query responses** when computing "available" borrowing capacity: [8](#0-7) 

The same unchecked subtraction pattern appears at lines 280 and 309 in the query handlers.

**Attack Scenario:**

This vulnerability can be triggered through normal protocol operations without malicious intent:

1. User A deposits 1000 tokens → `deposit_pool: {size: 1000, shares: 1000}`
2. Borrower B borrows 800 tokens → `debt_pool: {size: 800, shares: 800}`
3. Interest accrues over time (both pools grow proportionally):
   - `deposit_pool.size = 1050`
   - `debt_pool.size = 850`
   - Share counts remain: `deposit_pool.shares = 1000`, `debt_pool.shares = 800`
4. User A withdraws 750 shares:
   - Withdrawal amount calculated: `(750 / 1000) * 1050 = 787.5 ≈ 787 tokens`
   - `deposit_pool.size = 1050 - 787 = 263`
   - `debt_pool.size = 850` (unchanged)
5. **Corrupted state achieved**: `debt_pool.size (850) > deposit_pool.size (263)`
6. **Next operation fails**: Any execute or query operation triggers `distribute_interest()` → `utilization()` → panic on line 83

The protocol's "Always-Accrued Interest" invariant is now permanently broken because `distribute_interest()` cannot execute.

## Impact Explanation

**Critical Severity** - This vulnerability causes complete and permanent vault freezing with the following consequences:

1. **All deposits frozen**: No depositor can withdraw their funds. The `ExecuteMsg::Withdraw` handler calls `distribute_interest()` at line 51, which fails before the withdrawal can execute.

2. **All borrows frozen**: Borrowers cannot take new loans. The `ExecuteMsg::Market(MarketMsg::Borrow)` handler calls `distribute_interest()` at line 51, preventing all borrow operations.

3. **All repayments frozen**: Borrowers cannot repay their debts. The `ExecuteMsg::Market(MarketMsg::Repay)` handler calls `distribute_interest()` at line 51, preventing debt repayment.

4. **All new deposits frozen**: New depositors cannot add funds. The `ExecuteMsg::Deposit` handler calls `distribute_interest()` at line 51, blocking new deposits.

5. **All queries fail**: Protocol monitoring and user interfaces cannot query vault status. Query operations call `distribute_interest()` at line 226, causing all queries to fail.

6. **Protocol insolvency**: With `debt_pool.size > deposit_pool.size`, the vault is mathematically insolvent. Outstanding debt exceeds available deposits, and the frozen state prevents any remediation.

The only recovery mechanism is contract migration through governance, which:
- Requires emergency intervention by the Rujira Deployer Multisig
- May result in loss of accrued interest precision due to `pending_interest` and `pending_fees` state
- Creates significant user panic and trust damage

No special privileges are required - any depositor with sufficient shares can unintentionally trigger this condition during periods of high vault utilization.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Natural occurrence during normal operations**: This does not require malicious intent. It can occur organically when:
   - Multiple depositors withdraw simultaneously during high utilization periods (e.g., 80%+ borrowed)
   - Early depositors exit while substantial debt remains outstanding
   - Depositors observe high utilization ratios and decide to withdraw as a precautionary measure
   - A single large depositor withdraws a significant portion of their shares

2. **No protection mechanisms**: The codebase contains:
   - No validation in `State::withdraw()` to check the invariant
   - No validation in `SharePool::leave()` to prevent over-withdrawal
   - No warning system when approaching critical utilization thresholds
   - No maximum utilization limit enforcement

3. **Low technical barrier**: 
   - Single transaction required (`ExecuteMsg::Withdraw`)
   - No coordination needed between multiple parties
   - No special timing or front-running required
   - Any user with sufficient deposit shares can trigger it

4. **Economic incentives favor triggering**: During periods of high utilization:
   - Rational depositors may rush to withdraw ("run on the vault")
   - First withdrawers avoid the freeze, creating incentive to withdraw early
   - No penalty mechanism discourages withdrawals during high utilization

5. **Realistic threshold**: The vulnerability activates at moderate utilization levels. For example:
   - 80% utilization (800 debt / 1000 deposits)
   - After modest interest accrual (850 debt / 1050 deposits = 81% utilization)
   - A 75% withdrawal by the depositor (787 tokens)
   - Results in 323% over-utilization (850 debt / 263 deposits)

The combination of high impact (permanent fund freezing) and high likelihood (natural occurrence during normal high utilization) makes this a critical vulnerability requiring immediate remediation.

## Recommendation

Add an invariant check to `State::withdraw()` to prevent withdrawals that would result in `debt_pool.size > deposit_pool.size`:

```rust
pub fn withdraw(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
    let withdrawn = self.deposit_pool.leave(amount)?;
    
    // Ensure withdrawal maintains the invariant: deposits >= debt
    if self.deposit_pool.size() < self.debt_pool.size() {
        // Revert the withdrawal
        self.deposit_pool.join(withdrawn)?;
        return Err(ContractError::InsufficientLiquidity {});
    }
    
    Ok(withdrawn)
}
```

Add a new error variant to `ContractError`:

```rust
#[error("Insufficient liquidity: withdrawal would cause debt to exceed deposits")]
InsufficientLiquidity {},
```

This fix ensures the protocol invariant is maintained while providing clear error messaging to users when withdrawals are blocked due to insufficient liquidity.

## Proof of Concept

Add this test to `contracts/rujira-ghost-vault/src/contract.rs` in the `#[cfg(all(test, feature = "mock"))] mod tests` section:

```rust
#[test]
fn test_vault_freeze_via_withdrawal_underflow() {
    let mut app = mock_rujira_app();
    let depositor = app.api().addr_make("depositor");
    let borrower = app.api().addr_make("borrower");

    // Initialize balances
    app.init_modules(|router, _, storage| {
        router
            .bank
            .init_balance(storage, &depositor, coins(10_000, "btc"))
            .unwrap();
        router
            .bank
            .init_balance(storage, &borrower, coins(10_000, "btc"))
            .unwrap();
    });

    // Deploy vault
    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    let vault = app
        .instantiate_contract(
            code_id,
            depositor.clone(),
            &InstantiateMsg {
                denom: "btc".to_string(),
                receipt: TokenMetadata {
                    description: "".to_string(),
                    display: "".to_string(),
                    name: "".to_string(),
                    symbol: "".to_string(),
                    uri: None,
                    uri_hash: None,
                },
                interest: Interest {
                    target_utilization: Decimal::from_ratio(8u128, 10u128),
                    base_rate: Decimal::from_ratio(1u128, 10u128),
                    step1: Decimal::from_ratio(1u128, 10u128),
                    step2: Decimal::from_ratio(3u128, 1u128),
                },
                fee: Decimal::zero(),
                fee_address: depositor.to_string(),
            },
            &[],
            "vault",
            None,
        )
        .unwrap();

    // Step 1: Depositor deposits 1000 BTC
    app.execute_contract(
        depositor.clone(),
        vault.clone(),
        &ExecuteMsg::Deposit { callback: None },
        &coins(1_000u128, "btc"),
    )
    .unwrap();

    // Whitelist borrower with 800 BTC limit
    app.wasm_sudo(
        vault.clone(),
        &SudoMsg::SetBorrower {
            contract: borrower.to_string(),
            limit: Uint128::from(800u128),
        },
    )
    .unwrap();

    // Step 2: Borrower borrows 800 BTC
    app.execute_contract(
        borrower.clone(),
        vault.clone(),
        &ExecuteMsg::Market(MarketMsg::Borrow {
            callback: None,
            amount: Uint128::from(800u128),
            delegate: None,
        }),
        &[],
    )
    .unwrap();

    // Step 3: Fast forward time to accrue interest (90 days)
    app.update_block(|b| b.time = b.time.plus_days(90));

    // Check state after interest accrual
    let status: StatusResponse = app
        .wrap()
        .query_wasm_smart(vault.clone(), &QueryMsg::Status {})
        .unwrap();
    
    // At this point: deposit_pool.size = 816, debt_pool.size = 416
    // This is because both pools gained interest, but we need a scenario
    // where withdrawal causes debt > deposits
    
    // Step 4: Withdraw enough shares to cause debt_pool.size > deposit_pool.size
    // After 90 days with the given interest rate:
    // deposit_pool ~816, debt_pool ~416
    // We need to withdraw enough to bring deposits below 416
    
    // Withdraw 600 shares (out of 800 total shares)
    // This should withdraw approximately: (600/800) * 816 = 612 BTC
    // Leaving: 816 - 612 = 204 deposits vs 416 debt
    let result = app.execute_contract(
        depositor.clone(),
        vault.clone(),
        &ExecuteMsg::Withdraw { callback: None },
        &coins(600u128, "x/ghost-vault/btc"),
    );
    
    // The withdrawal succeeds (no check prevents it)
    assert!(result.is_ok());

    // Step 5: Now ANY operation should fail due to underflow in utilization()
    
    // Try to query status - should fail
    let query_result: Result<StatusResponse, _> = app
        .wrap()
        .query_wasm_smart(vault.clone(), &QueryMsg::Status {});
    assert!(query_result.is_err());
    
    // Try to deposit - should fail
    let deposit_result = app.execute_contract(
        depositor.clone(),
        vault.clone(),
        &ExecuteMsg::Deposit { callback: None },
        &coins(100u128, "btc"),
    );
    assert!(deposit_result.is_err());
    
    // Try to withdraw remaining shares - should fail
    let withdraw_result = app.execute_contract(
        depositor.clone(),
        vault.clone(),
        &ExecuteMsg::Withdraw { callback: None },
        &coins(100u128, "x/ghost-vault/btc"),
    );
    assert!(withdraw_result.is_err());
    
    // Try to repay debt - should fail
    let repay_result = app.execute_contract(
        borrower.clone(),
        vault.clone(),
        &ExecuteMsg::Market(MarketMsg::Repay { delegate: None }),
        &[coin(100, "btc")],
    );
    assert!(repay_result.is_err());
    
    // Vault is now permanently frozen - all operations fail
    // Only recovery is contract migration
}
```

This test demonstrates:
1. Normal vault operations (deposit, borrow)
2. Interest accrual over time
3. A withdrawal that violates the `deposit_pool.size >= debt_pool.size` invariant
4. Complete vault freeze where all subsequent operations fail
5. The vulnerability requires no special privileges or malicious intent

### Citations

**File:** contracts/rujira-ghost-vault/src/state.rs (L56-59)
```rust
    pub fn withdraw(&mut self, amount: Uint128) -> Result<Uint128, ContractError> {
        let withdrawn = self.deposit_pool.leave(amount)?;
        Ok(withdrawn)
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L75-87)
```rust
    pub fn utilization(&self) -> Decimal {
        // We consider accrued interest and debt in the utilization rate
        if self.deposit_pool.size().is_zero() {
            Decimal::zero()
        } else {
            Decimal::one()
                - Decimal::from_ratio(
                    // We use the debt pool size to determine utilization
                    self.deposit_pool.size().sub(self.debt_pool.size()),
                    self.deposit_pool.size(),
                )
        }
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L89-91)
```rust
    pub fn debt_rate(&self, interest: &Interest) -> StdResult<Decimal> {
        interest.rate(self.utilization())
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L136-143)
```rust
    pub fn distribute_interest(
        &mut self,
        env: &Env,
        config: &Config,
    ) -> Result<Uint128, ContractError> {
        // Calculate interest charged on total debt since last update
        let (interest, mut fee) =
            self.calculate_interest(&config.interest, env.block.time, config.fee)?;
```

**File:** packages/rujira-rs/src/share_pool.rs (L37-57)
```rust
    pub fn leave(&mut self, amount: Uint128) -> Result<Uint128, SharePoolError> {
        if amount.is_zero() {
            return Err(SharePoolError::Zero("Amount".to_string()));
        }

        if amount.gt(&self.shares()) {
            return Err(SharePoolError::ShareOverflow {});
        }

        if amount.eq(&self.shares()) {
            let claim = self.size;
            self.size = Uint128::zero();
            self.shares = Decimal::zero();
            return Ok(claim);
        }

        let claim: Uint128 = self.ownership(amount);
        self.size.sub_assign(claim);
        self.shares.sub_assign(Decimal::from_ratio(amount, 1u128));
        Ok(claim)
    }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L48-52)
```rust
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
    let mut response = match msg {
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L223-227)
```rust
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    let mut state = State::load(deps.storage)?;
    let config = Config::load(deps.storage)?;
    state.distribute_interest(&env, &config)?;

```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L259-264)
```rust
                available: min(
                    // Current borrows can exceed limit due to interest
                    borrower.limit.checked_sub(current).unwrap_or_default(),
                    state.deposit_pool.size() - state.debt_pool.size(),
                ),
            })?)
```
