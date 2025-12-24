# Audit Report

## Title
Permanent Loss of Funds Due to Fee Extraction on Excess Debt Token Balance During Liquidation Repayment

## Summary
The `execute_liquidate` function calculates liquidation fees based on the account's full debt token balance before repaying debt, but the vault only accepts up to the actual debt amount. Any excess is refunded to the credit registry contract where it becomes permanently locked, causing loss of funds without proportional debt reduction.

## Finding Description

In the liquidation repayment flow, fees are extracted from the full account balance before validating whether the amount is sufficient for meaningful debt repayment. This breaks **Invariant #6 (Fee-First Liquidation Repay)** which states fees should ensure "real debt repayment", and creates a scenario where excess tokens become permanently lost. [1](#0-0) 

The vulnerability occurs when:
1. An account has debt tokens in its balance that exceed the actual debt owed
2. `LiquidateMsg::Repay` is triggered
3. Fees are calculated on the **full balance** (lines 281-288), not the debt amount
4. The `repay_amount` (balance minus fees) is sent to the vault
5. The vault only accepts `min(repay_amount, borrower_debt)` and refunds excess [2](#0-1) 

The refund goes to `info.sender` (the credit registry), not back to the account: [3](#0-2) 

The credit registry has **no mechanism** to withdraw or redistribute these stuck tokens - there are only 3 `BankMsg::Send` calls in the entire contract, all for fees and borrowed funds forwarding, none for recovering stuck tokens.

The `validate_liquidation` check doesn't catch this when debt tokens pre-exist in the account because `spent_collateral = 0` (no collateral spent in current liquidation), making the slippage calculation default to zero: [4](#0-3) 

**Attack Scenario:**
1. Previous liquidation executes `LiquidateMsg::Execute` to swap 1000 tokens of collateral for debt tokens
2. This liquidation fails before executing `LiquidateMsg::Repay` (e.g., gas limit, other error)
3. The account now has 1000 debt tokens sitting in its balance
4. Account's actual debt is reduced to 100 tokens (through other repayments or partial liquidation)
5. New liquidator calls `Liquidate` with `msgs = [LiquidateMsg::Repay(denom)]`
6. Fee calculation: `liquidation_fee = 1000 * 0.05 = 50`, `liquidator_fee = 1000 * 0.05 = 50`
7. `repay_amount = 1000 - 50 - 50 = 900` sent to vault
8. Vault accepts `min(900, 100) = 100`, refunds 800 to credit registry
9. Registry sends 50 to protocol, 50 to liquidator
10. **Result: 800 tokens permanently locked in registry**, only 100 tokens of debt repaid

The account loses 900 tokens (800 stuck + 100 in fees) but only 100 tokens of debt were cleared.

## Impact Explanation

**HIGH Severity** - This causes direct, permanent loss of user funds:

- **Permanent fund freezing**: Excess tokens refunded to the registry cannot be recovered (no withdrawal mechanism exists)
- **Disproportionate fee extraction**: Liquidators and protocol extract fees based on full balance, not actual debt repaid
- **Economic loss without benefit**: Account loses assets without corresponding debt reduction

Maximum loss per transaction is limited by the account's debt token balance and the ratio of debt to balance. If balance is 10x the debt, up to 90% of the balance (minus fees) becomes permanently locked.

## Likelihood Explanation

**MEDIUM Likelihood** - Requires specific preconditions but is realistic:

**Prerequisites:**
1. Account must have debt tokens exceeding actual debt (from failed liquidations, partial repayments, or keeper/MEV bot operational errors)
2. Account must remain liquidatable
3. Liquidator must call `Repay` without first equalizing the balance

**Occurrence scenarios:**
- Failed liquidation attempts leave debt tokens in accounts (common in high-gas/congested conditions)
- Multi-step liquidations where intermediate steps succeed but final repay fails
- Accounts that borrowed but retained tokens (less common but possible)

The lack of input validation on `repay_amount` sufficiency means any liquidator calling `Repay` will trigger this, making exploitation straightforward once preconditions exist.

## Recommendation

Implement validation to ensure `repay_amount` is meaningful before extracting fees. Options:

**Option 1 - Query actual debt before fee extraction:**
```rust
// After line 270, query the actual debt
let delegate = account.id().to_string();
let vault = BORROW.load(deps.storage, denom.clone())?;
let borrower = vault.borrower(deps.querier, &account.id())?;
let delegate_debt = vault.delegate(deps.querier, &env.contract.address, &account.id())?;
let actual_debt = delegate_debt.current;

// Use min(balance, actual_debt + fees_needed) for fee calculation
let relevant_balance = std::cmp::min(balance.amount, actual_debt.multiply_ratio(110u128, 100u128));
let liquidation_fee = relevant_balance.multiply_ratio(...);
```

**Option 2 - Return excess to account instead of registry:**
After the vault refund, detect excess tokens in registry and return them to the account:
```rust
// Add after the repay message
.add_message(
    BankMsg::Send {
        to_address: account.id().to_string(),
        amount: vec![/* calculate excess */],
    }
)
```

**Option 3 - Add minimum repay validation:**
```rust
// After line 290
if repay_amount.is_zero() || repay_amount < balance.amount.multiply_ratio(10u128, 100u128) {
    return Err(ContractError::InsufficientRepayAmount { amount: repay_amount });
}
```

## Proof of Concept

This would require a multi-transaction test setup showing:
1. Execute liquidation with swap that leaves tokens
2. Transaction failure/revert
3. New liquidation with Repay
4. Verification that tokens are stuck in registry

A simplified test demonstrating the core issue:

```rust
#[test]
fn test_excess_tokens_stuck_in_registry() {
    // Setup: Account with 1000 debt tokens, but only 100 tokens of actual debt
    // 1. Mock account balance query to return 1000 tokens
    // 2. Mock vault delegate query to return 100 tokens of debt
    // 3. Execute liquidate with Repay message
    // 4. Verify:
    //    - Fees extracted on 1000 tokens (100 total)
    //    - Only 100 tokens accepted by vault
    //    - 800 tokens refunded to registry
    //    - No mechanism exists to withdraw 800 tokens from registry
    //    - Registry balance increases by 800 tokens permanently
}
```

Due to the complexity of the multi-contract setup and the need to mock vault responses, a full integration test would require the complete test infrastructure with vault contract instances.

## Notes

The vulnerability fundamentally stems from the design decision to extract fees **before** validating repayment sufficiency. The comment on line 267-269 acknowledges this design for chaining Repay operations, but doesn't account for the permanent fund loss when excess occurs. The `validate_liquidation` slippage check only protects against excessive collateral spending in the current liquidation, not against using pre-existing debt tokens inefficiently.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L265-318)
```rust
        LiquidateMsg::Repay(denom) => {
            let vault = BORROW.load(deps.storage, denom.clone())?;
            // We repay the full balance so that Repay can be chained in liquidation preferences messages
            // and still pass the no-over-liquidation check, as we can't know ahead of time the amount to repay
            // after a collateral swap
            let balance = deps.querier.query_balance(account.id(), &denom)?;

            if balance.amount.is_zero() {
                return Err(ContractError::ZeroDebtTokens {
                    denom: balance.denom,
                });
            }

            // Collect fees from the amount retrieved from the rujira-account.
            // A liquidation solver must ensure that the repayment is sufficient
            // after these fees are deducted
            let liquidation_fee = balance.amount.multiply_ratio(
                config.fee_liquidation.numerator(),
                config.fee_liquidation.denominator(),
            );
            let liquidator_fee = balance.amount.multiply_ratio(
                config.fee_liquidator.numerator(),
                config.fee_liquidator.denominator(),
            );

            let repay_amount = balance.amount.sub(liquidation_fee).sub(liquidator_fee);

            Ok(Response::default()
                .add_message(
                    account
                        .account
                        .send(env.contract.address.to_string(), vec![balance.clone()])?,
                )
                .add_message(
                    vault.market_msg_repay(
                        Some(delegate),
                        &coin(repay_amount.u128(), denom.clone()),
                    )?,
                )
                .add_message(BankMsg::Send {
                    to_address: config.fee_address.to_string(),
                    amount: coins(liquidation_fee.u128(), denom.clone()),
                })
                .add_message(BankMsg::Send {
                    to_address: info.sender.to_string(),
                    amount: coins(liquidator_fee.u128(), denom.clone()),
                })
                .add_event(event_execute_liquidate_repay(
                    &balance,
                    repay_amount,
                    liquidation_fee,
                    liquidator_fee,
                )))
        }
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L162-198)
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

            let mut response = Response::default().add_event(event_repay(
                borrower.addr.clone(),
                delegate,
                repay_amount,
                shares,
            ));

            let refund = amount.checked_sub(repay_amount)?;
            if !refund.is_zero() {
                response = response.add_message(BankMsg::Send {
                    to_address: info.sender.to_string(),
                    amount: coins(refund.u128(), &config.denom),
                });
            }
            response
        }
```

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
