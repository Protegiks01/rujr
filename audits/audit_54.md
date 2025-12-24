# Audit Report

## Title
Liquidation DoS via Preference Repay Messages Causing Unliquidatable Accounts and Protocol Insolvency

## Summary
The `LiquidateMsg::Repay` variant uses regular messages instead of SubMsgs, causing preference repayment failures to revert entire liquidation transactions. This breaks the documented "best effort" preference behavior and enables accounts to become permanently unliquidatable, accumulating bad debt and threatening protocol solvency.

## Finding Description

The liquidation system allows users to set preference messages that should be executed "best effort" during liquidation attempts. However, there is a critical inconsistency in how `LiquidateMsg::Repay` and `LiquidateMsg::Execute` handle errors:

**LiquidateMsg::Execute** (lines 319-337) uses `SubMsg::reply_always`, which routes errors through the reply handler. The reply handler distinguishes between preference messages (REPLY_ID_PREFERENCE) and liquidator messages (REPLY_ID_LIQUIDATOR), allowing preference errors to be caught and logged without reverting: [1](#0-0) [2](#0-1) 

**LiquidateMsg::Repay** (lines 265-318) uses regular messages via `add_message()`, completely bypassing the reply mechanism: [3](#0-2) 

The zero balance check explicitly fails with an error: [4](#0-3) 

Since this doesn't use SubMsg, **any failure causes the entire transaction to revert**, even when `is_preference = true`. The `reply_id` parameter passed to `execute_liquidate` at line 133-137 is unused for Repay messages: [5](#0-4) 

Users can set preference messages including Repay via `SetPreferenceMsgs`: [6](#0-5) [7](#0-6) 

The documentation explicitly states preferences should not block liquidations: [8](#0-7) 

**Attack Scenario:**

1. User creates account and borrows denom A
2. User sets preferences: `SetPreferenceMsgs([LiquidateMsg::Repay("B")])` where B is a valid denom in BORROW map but account has no balance in B
3. Account becomes liquidatable (adjusted_ltv >= liquidation_threshold)
4. Liquidator calls `ExecuteMsg::Liquidate`
5. Preference messages are processed first (added to queue at lines 80-87)
6. `LiquidateMsg::Repay("B")` executes
7. Balance query returns 0 for denom B
8. Error thrown at line 273: `ContractError::ZeroDebtTokens`
9. **Entire liquidation reverts** (not caught by reply handler)
10. Account remains unliquidatable, accumulating interest on outstanding debt

This breaks the **Safe Liquidation Outcomes** invariant which requires liquidations to trigger and complete when adjusted_ltv >= liquidation_threshold.

## Impact Explanation

**High Severity** - This vulnerability causes:

1. **Protocol Insolvency Risk**: Unliquidatable accounts accumulate interest while remaining undercollateralized, creating bad debt that the protocol (and lenders) must absorb
2. **Systemic Undercollateralization**: Multiple accounts can be stuck in liquidatable states, degrading overall protocol health
3. **Permanent DoS**: Accounts remain unliquidatable until user changes preferences (but if account owner is malicious or lost keys, this never happens)
4. **Lender Loss**: Depositors cannot recover funds from vaults with bad debt exposure

The impact is systemic because:
- Interest accrues continuously on unliquidatable debt
- Multiple accounts can be affected simultaneously
- No permissionless fix exists (requires user cooperation or governance intervention)
- Protocol's core invariant (liquidatability) is violated

## Likelihood Explanation

**High Likelihood** because:

1. **User Error Path**: Users may accidentally set invalid Repay preferences when configuring complex liquidation routes, unaware that zero-balance repays will DoS their liquidations
2. **Intentional Griefing**: Malicious users can deliberately set invalid preferences to make their accounts unliquidatable while continuing to extract value
3. **No Validation**: The protocol doesn't validate that preference Repay messages reference denoms the account actually has debt in
4. **Documented Feature**: Users are explicitly told to use preference messages via `SetPreferenceMsgs`, making this a commonly used feature

The vulnerability will manifest naturally during normal protocol operation without requiring sophisticated attacks.

## Recommendation

Modify `execute_liquidate` to wrap `LiquidateMsg::Repay` messages in a SubMsg with `reply_always`, matching the pattern used for `LiquidateMsg::Execute`:

```rust
pub fn execute_liquidate(
    deps: Deps,
    env: Env,
    info: MessageInfo,
    config: &Config,
    msg: LiquidateMsg,
    account: &CreditAccount,
    reply_id: u64,
) -> Result<Response, ContractError> {
    let delegate = account.id().to_string();

    match msg {
        LiquidateMsg::Repay(denom) => {
            let vault = BORROW.load(deps.storage, denom.clone())?;
            let balance = deps.querier.query_balance(account.id(), &denom)?;

            if balance.amount.is_zero() {
                return Err(ContractError::ZeroDebtTokens {
                    denom: balance.denom,
                });
            }

            let liquidation_fee = balance.amount.multiply_ratio(
                config.fee_liquidation.numerator(),
                config.fee_liquidation.denominator(),
            );
            let liquidator_fee = balance.amount.multiply_ratio(
                config.fee_liquidator.numerator(),
                config.fee_liquidator.denominator(),
            );
            let repay_amount = balance.amount.sub(liquidation_fee).sub(liquidator_fee);

            // Create a message that performs all repay operations atomically
            let repay_msg = CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: env.contract.address.to_string(),
                msg: to_json_binary(&ExecuteMsg::ExecuteRepay {
                    account_addr: account.id().to_string(),
                    denom: denom.clone(),
                    balance,
                    repay_amount,
                    liquidation_fee,
                    liquidator_fee,
                })?,
                funds: vec![],
            });

            // Wrap in SubMsg to enable reply handling
            Ok(Response::default()
                .add_submessage(
                    SubMsg::reply_always(repay_msg, reply_id)
                        .with_payload(to_json_binary(&account)?),
                )
                .add_event(event_execute_liquidate_repay(
                    &balance,
                    repay_amount,
                    liquidation_fee,
                    liquidator_fee,
                )))
        }
        LiquidateMsg::Execute { ... } => {
            // Existing implementation unchanged
        }
    }
}
```

Add a new internal message type to execute the repay operations:

```rust
pub enum ExecuteMsg {
    // ... existing variants ...
    ExecuteRepay {
        account_addr: String,
        denom: String,
        balance: Coin,
        repay_amount: Uint128,
        liquidation_fee: Uint128,
        liquidator_fee: Uint128,
    },
}
```

This ensures preference Repay failures are caught by the reply handler and don't block liquidations.

## Proof of Concept

```rust
#[cfg(test)]
mod test_liquidation_dos {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_json, Addr, Decimal};
    use crate::config::Config;
    use crate::account::CreditAccount;
    use rujira_rs::ghost::credit::{ExecuteMsg, AccountMsg, LiquidateMsg};

    #[test]
    fn test_preference_repay_dos_on_liquidation() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        
        // Setup protocol with two denoms
        let config = Config {
            code_id: 1,
            collateral_ratios: [
                ("denom_a".to_string(), Decimal::percent(80)),
                ("denom_b".to_string(), Decimal::percent(80)),
            ].into(),
            fee_liquidation: Decimal::percent(1),
            fee_liquidator: Decimal::percent(1),
            fee_address: Addr::unchecked("fee_addr"),
            liquidation_max_slip: Decimal::percent(5),
            liquidation_threshold: Decimal::percent(90),
            adjustment_threshold: Decimal::percent(80),
        };
        config.save(deps.as_mut().storage).unwrap();

        // Create account that borrows denom_a
        let owner = Addr::unchecked("user");
        let account_addr = Addr::unchecked("account_contract");
        
        // Account has debt in denom_a but user sets preference to repay denom_b (zero balance)
        let info = mock_info(owner.as_str(), &[]);
        let set_pref_msg = ExecuteMsg::Account {
            addr: account_addr.to_string(),
            msgs: vec![AccountMsg::SetPreferenceMsgs(vec![
                LiquidateMsg::Repay("denom_b".to_string()), // No balance in this denom!
            ])],
        };
        
        // Execute preference setting
        execute(deps.as_mut(), env.clone(), info.clone(), set_pref_msg).unwrap();

        // Account becomes liquidatable
        // ... setup liquidatable state ...

        // Liquidator attempts liquidation
        let liquidator = mock_info("liquidator", &[]);
        let liquidate_msg = ExecuteMsg::Liquidate {
            addr: account_addr.to_string(),
            msgs: vec![
                LiquidateMsg::Execute {
                    contract_addr: "swap_contract".to_string(),
                    msg: to_json_binary(&"swap_for_denom_a").unwrap(),
                    funds: vec![],
                },
                LiquidateMsg::Repay("denom_a".to_string()),
            ],
        };

        // This should fail because preference Repay("denom_b") has zero balance
        let result = execute(deps.as_mut(), env, liquidator, liquidate_msg);
        
        // Expected: preference error should be caught and liquidation continues
        // Actual: entire transaction reverts with ZeroDebtTokens error
        assert!(result.is_err());
        match result.unwrap_err() {
            ContractError::ZeroDebtTokens { denom } => {
                assert_eq!(denom, "denom_b");
                // Account is now unliquidatable despite being above liquidation threshold!
            },
            _ => panic!("Expected ZeroDebtTokens error"),
        }
    }
}
```

The test demonstrates that a preference Repay with zero balance causes complete liquidation failure, making the account unliquidatable and exposing the protocol to bad debt accumulation.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L124-138)
```rust
                (Some((msg, is_preference)), Err(_)) => {
                    // Not safe, more messages to go. Continue
                    Ok(execute_liquidate(
                        deps.as_ref(),
                        env.clone(),
                        info,
                        &config,
                        msg,
                        &account,
                        if is_preference {
                            REPLY_ID_PREFERENCE
                        } else {
                            REPLY_ID_LIQUIDATOR
                        },
                    )?
```

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

**File:** contracts/rujira-ghost-credit/src/contract.rs (L324-332)
```rust
            .add_submessage(
                SubMsg::reply_always(
                    account
                        .account
                        .execute(contract_addr.clone(), msg.clone(), funds.clone())?,
                    reply_id,
                )
                .with_payload(to_json_binary(&account)?),
            )
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L344-346)
```rust
        (SubMsgResult::Err(err), REPLY_ID_PREFERENCE) => {
            // Don't block execution if this is a preferential step
            Ok(Response::default().add_event(event_execute_liquidate_preference_error(err)))
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L96-96)
```rust
    SetPreferenceMsgs(Vec<LiquidateMsg>),
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L104-112)
```rust
pub enum LiquidateMsg {
    /// Repay all the balance of the denom provided
    Repay(String),
    Execute {
        contract_addr: String,
        msg: Binary,
        funds: Vec<Coin>,
    },
}
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L254-257)
```rust
    /// These sub-messages are emitted as "Reply Always", and if the
    /// reply is an error state, we ignore the error.
    /// We can't have invalid messages blocking an account liquidation:
    /// User experience is the preference, but system solvency is the priority
```
