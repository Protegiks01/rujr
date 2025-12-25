# Audit Report

## Title
Over-Repayment Results in Permanent Loss of User Funds Due to Refund Misdirection

## Summary
When users repay more debt than they owe through `AccountMsg::Repay`, the vault correctly caps the repayment and refunds the excess. However, the refund is sent to the credit registry contract instead of the user's account, resulting in permanent loss of funds as the registry has no mechanism to return or withdraw these stuck tokens.

## Finding Description

The vulnerability exists in the architectural design of the repayment flow between the credit registry and vault contracts.

When a user initiates a repayment via `ExecuteMsg::Account` with `AccountMsg::Repay`, the credit registry's `execute_account` function creates two messages: [1](#0-0) 

The first message transfers tokens from the user's account contract to the credit registry contract itself (`env.contract.address`). The second message calls the vault's `market_msg_repay`, which constructs a `WasmMsg::Execute` with the repayment amount attached as funds: [2](#0-1) 

When the vault processes this repayment, it caps the amount at the borrower's actual debt and calculates a refund: [3](#0-2) 

The critical flaw occurs in lines 192-195: the refund is sent to `info.sender`, which in this execution context is the **credit registry contract**, not the user or their account contract.

The credit registry contract has no mechanism to withdraw or return these stuck funds. Examining all available functions: [4](#0-3) 

Neither `ExecuteMsg` nor `SudoMsg` contains any function that could withdraw tokens from the credit registry contract. The stuck funds become permanently inaccessible.

**Execution Flow:**
1. User calls `ExecuteMsg::Account` with `AccountMsg::Repay(1000 tokens)` when owing 700 tokens
2. Credit registry receives 1000 tokens from user's account
3. Credit registry forwards 1000 tokens to vault via `WasmMsg::Execute`
4. Vault calculates: `repay_amount = min(1000, 700) = 700`, `refund = 300`
5. Vault refunds 300 tokens to `info.sender` (the credit registry)
6. **300 tokens permanently stuck in credit registry**

This violates the fundamental protocol invariant that user funds should always be recoverable.

## Impact Explanation

**Severity: Critical** - This results in direct, permanent loss of user funds.

- Any overpayment by users results in irretrievable loss of the excess amount
- Funds accumulate in the credit registry contract with no admin function to rescue them
- The vulnerability affects all users of the protocol who repay debt
- Can occur accidentally due to:
  - User error (wrong amount entered)
  - Race conditions with interest accrual (debt increases between transaction submission and execution)
  - UI bugs displaying incorrect debt amounts
  - Rounding differences in debt calculations

This qualifies as **Critical severity** under Code4rena standards as it represents direct loss of user funds with no recovery mechanism.

## Likelihood Explanation

**Likelihood: Medium-High**

While this requires user action to trigger, several realistic scenarios make it likely:

1. **Interest Accrual Race Condition**: Users query their debt, submit repayment, but interest accrues before execution. If users sent slightly more for safety, they lose the excess.

2. **UI/UX Issues**: Frontends might display debt amounts with rounding differences or stale data, leading to overpayment.

3. **Intentional Safety Margin**: Users might intentionally overpay slightly to ensure complete repayment, unaware of the permanent loss risk.

4. **No Warning System**: The protocol provides no warning or protection against overpayment, unlike traditional DeFi protocols.

The combination of realistic trigger conditions and lack of protective measures creates a medium-high probability of occurrence.

## Recommendation

Modify the repayment flow to refund excess payments directly to the user's account contract instead of the credit registry. Two possible solutions:

**Solution 1**: Have the vault refund to the delegate address (user's account) instead of info.sender:

```rust
if !refund.is_zero() {
    let refund_recipient = match delegate_address {
        Some(d) => d.to_string(),
        None => borrower.addr.to_string(),
    };
    response = response.add_message(BankMsg::Send {
        to_address: refund_recipient,
        amount: coins(refund.u128(), &config.denom),
    });
}
```

**Solution 2**: Modify the credit registry to handle refunds by adding the refund as a third message that sends from registry to user's account.

## Proof of Concept

Add this test to `contracts/rujira-ghost-credit/src/tests/contract.rs`:

```rust
#[test]
fn test_overpayment_loses_funds() {
    let mut app = mock_rujira_app();
    app.init_modules(|router, _, _| {
        router.stargate.with_prices(vec![
            ("USDC", Decimal::from_str("1.0").unwrap()),
        ]);
    });

    let owner = app.api().addr_make("owner");
    let fees = app.api().addr_make("fee");
    let credit = GhostCredit::create(&mut app, &owner, &fees);
    let account = create(&mut app, &credit, owner.clone());
    
    // Fund account with USDC
    app.send_tokens(
        owner.clone(),
        account.account.clone(),
        &coins(2000, USDC),
    ).unwrap();
    
    // Configure collateral and create vault
    credit.set_collateral(&mut app, USDC, "0.9");
    let vault = GhostVault::create(&mut app, &owner, USDC);
    vault.set_borrower(&mut app, credit.addr().as_str(), Uint128::MAX).unwrap();
    credit.set_vault(&mut app, &vault);
    
    // Deposit liquidity to vault
    vault.deposit(&mut app, &owner, 5000, USDC).unwrap();
    
    // Borrow 1000 USDC
    credit.account_borrow(&mut app, &account, 1000, USDC).unwrap();
    
    // Get credit registry balance before overpayment
    let registry_balance_before = app.wrap().query_balance(credit.addr(), USDC).unwrap();
    
    // Attempt to repay 1500 USDC when only owing 1000 USDC
    app.send_tokens(
        owner.clone(),
        account.account.clone(),
        &coins(1500, USDC),
    ).unwrap();
    
    credit.account(
        &mut app,
        &account,
        vec![AccountMsg::Repay(coin(1500, USDC))],
    ).unwrap();
    
    // Get credit registry balance after overpayment
    let registry_balance_after = app.wrap().query_balance(credit.addr(), USDC).unwrap();
    
    // The 500 USDC overpayment should be stuck in the credit registry
    let stuck_amount = registry_balance_after.amount.u128() - registry_balance_before.amount.u128();
    assert_eq!(stuck_amount, 500, "Excess funds should be stuck in credit registry");
    
    // Verify the account has zero debt
    let account_state = credit.query_account(&app, &account.account);
    assert_eq!(account_state.debts.len(), 0, "Debt should be fully repaid");
    
    // Verify the user cannot recover the stuck funds through any means
    // (No ExecuteMsg or SudoMsg exists to withdraw from credit registry)
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw in the payment routing design. The refund mechanism assumes the caller (`info.sender`) is the end user, but in Rujira's three-contract architecture, the credit registry acts as an intermediary that holds no funds of its own and has no withdrawal functions. This mismatch creates a permanent fund trap for overpayments.

### Citations

**File:** contracts/rujira-ghost-credit/src/contract.rs (L196-204)
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

**File:** contracts/rujira-ghost-vault/src/contract.rs (L162-196)
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
```

**File:** packages/rujira-rs/src/interfaces/ghost/credit/interface.rs (L28-126)
```rust
pub enum ExecuteMsg {
    Create {
        /// Provide a salt to create predictable Account addresses
        salt: Binary,
        /// Custom label to append to the Account contract on instantiation
        label: String,
        /// Tag to allow filtering of accounts when queried
        tag: String,
    },

    /// Executes msgs on the Account on behalf of the owner
    /// The account must have collateralizaion ratio < 1 after the message has been executed, to succeed
    Account { addr: String, msgs: Vec<AccountMsg> },

    /// NOOP function that checks position health against adjustment_threshold
    CheckAccount { addr: String },

    /// Liquidate the credit account
    /// Can only be called if the account is above a LTV of 1
    /// Will only succeed if the collateralizaion ratio drops either below 1, or by max_liquidate, whichever is smaller
    Liquidate {
        addr: String,
        msgs: Vec<LiquidateMsg>,
    },

    /// Internal entrypoint used to process LiquidateMsg's in sequence. Checks:
    ///     - Previous step against config.liquidation_max_slip
    /// This allows logic to eg read balances following prior LiquidateMsg executions
    /// If liquidation critera are met, then the execution of the queue halts:
    ///     - Account adjusted_ltv < config.liquidation_threshold
    ///     - Account adjusted_ltv >= adjustment_threshold
    /// If queue is empty then final check is made:
    ///     - Collaterals have all strictly decreased; no overliquidations
    DoLiquidate {
        addr: String,
        /// Vec of (msg, is_preference)
        /// When is_preference is set, errors will be ignored, logged and the next message in the queue will be processed
        queue: Vec<(LiquidateMsg, bool)>,
        /// Arbitrary payload to pass through from initial account load to be delivered to CheckLiquidate
        payload: Binary,
    },
}

impl ExecuteMsg {
    pub fn call(&self, address: &Addr) -> StdResult<CosmosMsg> {
        Ok(WasmMsg::Execute {
            contract_addr: address.to_string(),
            msg: to_json_binary(self)?,
            funds: vec![],
        }
        .into())
    }
}

#[cw_serde]
pub enum AccountMsg {
    Borrow(Coin),
    Repay(Coin),
    Execute {
        contract_addr: String,
        msg: Binary,
        funds: Vec<Coin>,
    },
    Send {
        to_address: String,
        funds: Vec<Coin>,
    },
    Transfer(String),
    SetPreferenceMsgs(Vec<LiquidateMsg>),
    SetPreferenceOrder {
        denom: String,
        after: Option<String>,
    },
}

#[cw_serde]
pub enum LiquidateMsg {
    /// Repay all the balance of the denom provided
    Repay(String),
    Execute {
        contract_addr: String,
        msg: Binary,
        funds: Vec<Coin>,
    },
}

#[cw_serde]
pub enum SudoMsg {
    SetVault {
        address: String,
    },

    SetCollateral {
        denom: String,
        collateralization_ratio: Decimal,
    },

    UpdateConfig(ConfigUpdate),
}
```
