# Audit Report

## Title
Missing Market Impact Controls and Error Types for User-Initiated Account Operations

## Summary
The Rujira Protocol implements market impact protection (`liquidation_max_slip`) for liquidations but provides no equivalent safeguards for user-initiated operations through `AccountMsg::Execute`. This creates an asymmetric risk model where users can execute arbitrarily large operations causing significant market impact without any protocol-level detection, size limits, or specific error types to prevent excessive single-transaction operations.

## Finding Description

The protocol implements a two-tier protection model that treats liquidations differently from regular account operations:

**Liquidations (Protected):** [1](#0-0) 

The `validate_liquidation` function enforces `liquidation_max_slip` and raises `LiquidationMaxSlipExceeded` error when slippage exceeds configured limits. [2](#0-1) 

**User Operations (Unprotected):** [3](#0-2) 

The `execute_account` handler for `AccountMsg::Execute` forwards arbitrary contract calls without any size validation or market impact checks. [4](#0-3) 

The account contract's error types contain only `Unauthorized`, with no market impact detection capabilities. [5](#0-4) 

The `sudo` entrypoint forwards messages without validation, relying entirely on the credit registry's checks.

**Attack Vector:**
Users can execute `AccountMsg::Execute` with arbitrarily large fund amounts to interact with swap contracts or other DeFi protocols. The only constraint is the post-operation LTV check: [6](#0-5) 

This allows operations to succeed as long as the final `adjusted_ltv < adjustment_threshold`, regardless of transaction size or market impact during execution.

## Impact Explanation

This design gap enables several attack vectors:

1. **Market Manipulation**: Users can execute extremely large swaps that significantly move market prices, potentially exploiting the temporary price impact for profit through coordinated external positions

2. **Oracle Price Pressure**: Large operations could temporarily skew oracle price feeds (even if trusted), creating arbitrage opportunities or enabling profitable liquidations of other positions

3. **Unfair Advantages**: Users with large collateral positions can create market conditions that benefit their external holdings while maintaining protocol compliance through LTV checks

4. **Slippage Extraction**: Users could sandwich their own large operations or coordinate with external actors to extract value from the market impact they create

The severity is **Medium** because:
- No direct theft of protocol funds occurs
- No permanent freezing of assets
- Enables economic manipulation and unfair competitive advantages
- Creates systemic risks if multiple large users coordinate operations
- Asymmetric protection model suggests potential design oversight

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

- Any credit account owner can exploit this immediately
- No special preconditions required beyond having collateral
- Simple to execute (single transaction with large amounts)
- Economically rational for users with external positions to hedge
- No technical complexity barriers

The only limitation is the amount of collateral available, but users with substantial positions can create significant market impact without protocol intervention.

## Recommendation

Implement symmetric market impact protection for both liquidations and user operations:

1. **Add Market Impact Error Types:**
```rust
// In contracts/rujira-ghost-credit/src/error.rs
#[error("Operation exceeds max transaction size: {amount}")]
MaxTransactionSizeExceeded { amount: Uint128 },

#[error("Operation max slip exceeded: {slip}")]
OperationMaxSlipExceeded { slip: Decimal },
```

2. **Add Configuration Parameters:**
```rust
// In contracts/rujira-ghost-credit/src/config.rs
pub struct Config {
    // ... existing fields
    pub operation_max_slip: Decimal,
    pub max_operation_size_usd: Option<Decimal>,
}
```

3. **Implement Validation in execute_account:**
```rust
// In contracts/rujira-ghost-credit/src/contract.rs
// Add validation before executing AccountMsg::Execute
match msg {
    AccountMsg::Execute { funds, .. } => {
        // Validate transaction size against limits
        let funds_usd = NativeBalance(funds.clone()).value_usd(deps.querier)?;
        if let Some(max_size) = config.max_operation_size_usd {
            ensure!(
                funds_usd <= max_size,
                ContractError::MaxTransactionSizeExceeded { amount: funds_usd }
            );
        }
        // ... existing execute logic
    }
    // ... other cases
}
```

4. **Add Post-Operation Slippage Validation:**
Similar to `validate_liquidation`, track collateral value before/after operations and enforce `operation_max_slip` limits.

## Proof of Concept

```rust
#[test]
fn test_unbounded_market_impact() {
    let (mut app, registry, accounts) = setup_test_environment();
    let user = accounts[0].clone();
    
    // User deposits 1M USD worth of collateral
    deposit_collateral(&mut app, &user, coin(1_000_000_000000, "USDC"));
    
    // User borrows 500k USD worth of assets
    borrow_from_vault(&mut app, &user, coin(500_000_000000, "DAI"));
    
    // User executes massive swap with entire collateral balance
    // This would cause significant market slippage but protocol allows it
    let result = app.execute_contract(
        user.owner.clone(),
        registry.address.clone(),
        &ExecuteMsg::Account {
            addr: user.account.to_string(),
            msgs: vec![AccountMsg::Execute {
                contract_addr: "swap_router".to_string(),
                msg: to_json_binary(&SwapMsg {
                    // Swap entire collateral balance
                    amount: coin(1_000_000_000000, "USDC"),
                }).unwrap(),
                funds: vec![coin(1_000_000_000000, "USDC")],
            }],
        },
        &[],
    );
    
    // Operation succeeds if final LTV < adjustment_threshold
    // No error is raised for excessive transaction size or market impact
    assert!(result.is_ok(), "Large operation executed without market impact checks");
    
    // In contrast, liquidations would fail with LiquidationMaxSlipExceeded
    // if they caused similar slippage, demonstrating the asymmetric protection
}
```

**Notes:**
- The asymmetric treatment suggests this may be a design oversight rather than intentional feature
- The existence of `liquidation_max_slip` protection demonstrates the protocol's awareness of market impact risks
- The absence of equivalent protections for user operations creates exploitable gaps
- The missing error types in `rujira-account/src/error.rs` prevent detection and limiting of excessive operations

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

**File:** contracts/rujira-ghost-credit/src/error.rs (L75-76)
```rust
    #[error("Max Slip exceeded during liquidation: #{slip}")]
    LiquidationMaxSlipExceeded { slip: Decimal },
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L151-164)
```rust
        ExecuteMsg::Account { addr, msgs } => {
            let mut account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            ensure_eq!(account.owner, info.sender, ContractError::Unauthorized {});
            let mut response = Response::default().add_event(event_execute_account(&account));
            for msg in msgs {
                let (messages, events) =
                    execute_account(deps.as_ref(), env.clone(), &config, msg, &mut account)?;
                response = response.add_messages(messages).add_events(events);
            }
            account.save(deps)?;

            Ok(response.add_message(ExecuteMsg::CheckAccount { addr }.call(&ca)?))
        }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L206-216)
```rust
        AccountMsg::Execute {
            contract_addr,
            msg,
            funds,
        } => {
            let event =
                event_execute_account_execute(&contract_addr, &msg, &NativeBalance(funds.clone()));
            Ok((
                vec![account.account.execute(contract_addr, msg, funds)?],
                vec![event],
            ))
```

**File:** contracts/rujira-account/src/error.rs (L4-11)
```rust
#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},
}
```

**File:** contracts/rujira-account/src/contract.rs (L33-34)
```rust
pub fn sudo(_deps: DepsMut, _env: Env, msg: CosmosMsg) -> Result<Response, ContractError> {
    Ok(Response::default().add_message(msg))
```
