# Audit Report

## Title
Over-Repayment Results in Permanent Loss of User Funds Due to Refund Misdirection

## Summary
When users repay more debt than they owe through `AccountMsg::Repay`, the vault correctly caps the repayment and refunds the excess. However, the refund is sent to the credit registry contract instead of the user's account, resulting in permanent loss of funds as the registry has no mechanism to return or withdraw these stuck tokens.

## Finding Description

The vulnerability exists in the interaction between the credit registry's repayment flow and the vault's refund mechanism. 

In the credit registry's `execute_account` function, when processing `AccountMsg::Repay`, two messages are created: [1](#0-0) 

The first message transfers funds from the user's account contract to the credit registry. The second message calls the vault's `market_msg_repay`, which constructs a `WasmMsg::Execute` with the repayment amount attached as funds: [2](#0-1) 

When the vault processes this repayment, it correctly caps the amount at the borrower's actual debt and calculates a refund: [3](#0-2) 

The critical flaw occurs on lines 192-196: the refund is sent to `info.sender`, which in this execution context is the credit registry contract, not the user or their account contract. The credit registry has no functions to withdraw or redistribute these stuck funds.

**Execution Flow:**
1. User calls `ExecuteMsg::Account` with `AccountMsg::Repay(1000 tokens)` when they only owe 700 tokens
2. Account contract → Credit registry: 1000 tokens transferred
3. Credit registry → Vault: 1000 tokens sent via `WasmMsg::Execute` 
4. Vault processes: `repay_amount = min(1000, 700) = 700`, `refund = 300`
5. Vault → Credit registry: 300 tokens refunded to `info.sender`
6. **300 tokens permanently stuck in credit registry with no recovery mechanism**

This breaks the fundamental invariant that user funds should always be recoverable and represents a direct loss of user assets.

## Impact Explanation

**Severity: High/Critical** - This results in direct, permanent loss of user funds.

- Any overpayment by users results in irretrievable loss of the excess amount
- Funds accumulate in the credit registry contract with no admin function to rescue them
- The vulnerability affects all users of the protocol who attempt to repay debt
- Could occur accidentally due to:
  - User error (wrong amount entered)
  - Race conditions with interest accrual (debt increases between tx submission and execution)
  - UI bugs showing incorrect debt amounts
  - Rounding differences in debt calculations

The impact is categorized as **direct loss of funds**, which qualifies as Critical severity under Code4rena standards. Users trust the protocol to handle their assets safely, and this flaw violates that trust by permanently confiscating overpaid amounts.

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires user action to trigger, several realistic scenarios make it likely to occur:

1. **Interest Accrual Race Condition**: User queries their debt (e.g., 1000 tokens), submits repayment transaction, but interest accrues before execution making actual debt 1005 tokens. If user sent 1000, no issue. But if they sent slightly more for safety (1010), they lose 5 tokens.

2. **UI/UX Issues**: Wallets or frontends might display debt amounts with rounding differences or fail to refresh debt state, leading users to submit incorrect amounts.

3. **Intentional Safety Margin**: Users might intentionally overpay slightly to ensure full repayment, unaware of the fund loss risk.

4. **Batch Operations**: Users repaying multiple positions might make calculation errors.

5. **No Warning System**: The protocol provides no warning or protection against overpayment, unlike traditional DeFi protocols that typically reject overpayments or immediately refund.

The combination of realistic trigger conditions and lack of protective measures makes this a high-probability issue.

## Recommendation

Implement one of the following fixes:

**Option 1 (Recommended): Forward refunds back to the account contract**

Modify the repayment flow to handle refunds by sending them back to the user's account:

In `execute_account` for `AccountMsg::Repay`, instead of directly calling the vault, use a two-step approach:
1. Call vault with funds
2. Query the credit registry balance before and after
3. If balance increased (refund received), send it back to the account

**Option 2: Reject over-repayments**

Query the vault for exact debt before creating the repay message and reject transactions where `amount > debt`. This prevents overpayment but may cause issues with interest accrual timing.

**Option 3: Add admin rescue function**

Implement an admin function to rescue stuck funds from the credit registry, though this introduces centralization risks.

**Recommended Implementation (Option 1):**

Modify the repay flow to use a callback pattern or add a cleanup step that checks for refunds and forwards them to the account contract. This preserves user experience while preventing fund loss.

## Proof of Concept

```rust
#[test]
fn test_overpayment_loses_funds() {
    let mut app = mock_rujira_app();
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::one()),
            ("BTC", Decimal::one()),
        ]);
    });

    let owner = app.api().addr_make("owner");
    let fees = app.api().addr_make("fee");
    
    // Setup credit system
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    credit.set_collateral(&mut app, USDC, "0.9");
    
    // Setup vault
    let vault = GhostVault::create(&mut app, &owner, USDC);
    vault.set_borrower(&mut app, credit.addr().as_str(), Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    vault.deposit(&mut app, &owner, 10000, USDC).unwrap();
    
    // Create account and add collateral
    let account = credit.create_account(&mut app, &owner, "", "", Binary::new(vec![0]));
    app.send_tokens(owner.clone(), account.account.clone(), &coins(2000, USDC)).unwrap();
    
    // Borrow 1000 USDC
    credit.account_borrow(&mut app, &account, 1000, USDC).unwrap();
    
    // Check debt is 1000
    let acc_query = credit.query_account(&app, &account.account);
    assert_eq!(acc_query.debts[0].debt.amount, Uint128::from(1000u128));
    
    // User attempts to repay 1500 USDC (500 more than owed)
    app.send_tokens(owner.clone(), account.account.clone(), &coins(1500, USDC)).unwrap();
    
    // Check balances before
    let credit_balance_before = app.wrap().query_balance(credit.addr(), USDC).unwrap();
    let account_balance_before = app.wrap().query_balance(&account.account, USDC).unwrap();
    
    // Execute overpayment
    credit.account_repay(&mut app, &account, 1500, USDC).unwrap();
    
    // Check balances after
    let credit_balance_after = app.wrap().query_balance(credit.addr(), USDC).unwrap();
    let account_balance_after = app.wrap().query_balance(&account.account, USDC).unwrap();
    
    // Verify debt is fully repaid
    let acc_query_after = credit.query_account(&app, &account.account);
    assert_eq!(acc_query_after.debts.len(), 0);
    
    // BUG: 500 USDC stuck in credit registry!
    // Expected: account should have received 500 back
    // Actual: credit registry received 500 and has no way to return it
    let stuck_funds = credit_balance_after.amount.checked_sub(credit_balance_before.amount).unwrap();
    assert_eq!(stuck_funds, Uint128::from(500u128), "500 USDC stuck in credit registry");
    
    // Account didn't receive refund
    assert!(account_balance_after.amount < Uint128::from(500u128), "Account didn't receive refund");
}
```

This test demonstrates that when a user overpays by 500 USDC, those funds become permanently stuck in the credit registry contract with no recovery mechanism.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L196-205)
```rust
        AccountMsg::Repay(coin) => {
            let vault = BORROW.load(deps.storage, coin.denom.clone())?;
            let msgs = vec![
                account
                    .account
                    .send(env.contract.address, vec![coin.clone()])?,
                vault.market_msg_repay(Some(delegate), &coin)?,
            ];
            Ok((msgs, vec![event_execute_account_repay(&coin)]))
        }
```

**File:** packages/rujira-rs/src/interfaces/ghost/vault/interface.rs (L188-194)
```rust
    pub fn market_msg_repay(
        &self,
        delegate: Option<String>,
        amount: &Coin,
    ) -> StdResult<CosmosMsg> {
        self.market_msg(MarketMsg::Repay { delegate }, vec![amount.clone()])
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
