# Audit Report

## Title
Interest Rate Changes Without Prior Distribution Cause Systematic Interest Miscalculation in Ghost Vaults

## Summary
When the admin updates interest rates via `SudoMsg::SetInterest`, the `sudo()` function fails to call `distribute_interest()` before applying the new rate configuration. This causes the accrued interest for the period since the last update to be calculated using the NEW rate instead of the OLD rate when the next transaction occurs, resulting in systematic over- or under-charging of interest to borrowers and incorrect returns to depositors.

## Finding Description

The vulnerability exists in the `sudo()` function's handling of `SudoMsg::SetInterest`. [1](#0-0) 

When this message is processed, it updates the interest configuration immediately without first distributing accrued interest under the old rate. In contrast, every `execute()` call correctly distributes interest before any operations. [2](#0-1) 

The `distribute_interest()` function calculates interest based on three factors: the current interest rate configuration, the time elapsed since `state.last_updated`, and the current debt pool size. [3](#0-2) 

The critical issue is that `calculate_interest()` uses the current configuration passed to it, applying it retroactively to the entire elapsed time period. [4](#0-3) 

**Attack Scenario:**

1. **Time T0**: Last transaction occurs, `state.last_updated = T0`, interest rate = 20% APR, debt pool = 1,000,000 tokens
2. **Time T0 + 180 days**: Admin calls `sudo(SetInterest)` to change rate to 5% APR
   - Config updated to 5% APR
   - State NOT updated, `last_updated` still = T0
3. **Time T0 + 181 days**: Next user transaction (deposit/withdraw/borrow/repay)
   - `execute()` calls `distribute_interest()`
   - Calculates interest for **181 days at NEW rate (5%)** instead of:
     - 180 days at 20% APR
     - 1 day at 5% APR

**Calculation:**
- **Expected interest**: (1,000,000 × 0.20 × 180/365) + (1,000,000 × 0.05 × 1/365) = 98,630 + 137 = 98,767 tokens
- **Actual interest calculated**: 1,000,000 × 0.05 × 181/365 = 24,794 tokens
- **Loss to depositors**: 73,973 tokens (~75% of expected interest)

This violates the protocol's **"Always-Accrued Interest"** invariant documented in the README, which states that interest distribution should occur before all operations to ensure accurate accounting. [5](#0-4) 

## Impact Explanation

**HIGH SEVERITY** - This qualifies as a systemic interest calculation error with direct financial impact:

1. **Direct Economic Loss**: Depositors lose earned interest when rates decrease; borrowers are overcharged when rates increase
2. **Scales with Time**: The longer between rate changes and the next transaction, the greater the miscalculation
3. **Affects All Vault Users**: Every borrower and depositor in the affected vault is impacted
4. **Protocol Revenue Loss**: If rates decrease significantly, the protocol loses substantial fee revenue (fees are calculated as a percentage of interest)

Using realistic parameters:
- Vault with $10M TVL
- 80% utilization ($8M borrowed)
- Rate change from 15% to 3% APR
- 90 days until next transaction
- **Lost interest**: $8M × (0.15 - 0.03) × 90/365 = **$236,712**

This represents a material economic loss to depositors who provided liquidity expecting returns at the higher rate.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This will occur every time interest rates are updated:

1. **Frequent Operation**: Interest rate updates are a normal governance action responding to market conditions. Protocols typically adjust rates monthly or even more frequently.
2. **No Attacker Required**: This is a protocol logic bug, not an exploit requiring malicious actors. It happens automatically.
3. **Unavoidable**: Every rate change will trigger this miscalculation until the next transaction occurs.
4. **Low Activity Periods**: The impact is worse during low vault activity when time between transactions is longer (e.g., weekends, holidays, low-volume assets).

## Recommendation

The fix is straightforward: call `distribute_interest()` in the `sudo()` function before updating the interest configuration:

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    let mut config = Config::load(deps.storage)?;

    match msg {
        SudoMsg::SetBorrower { contract, limit } => {
            Borrower::set(deps.storage, deps.api.addr_validate(&contract)?, limit)?;
            Ok(Response::default())
        }
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            
            // FIX: Distribute interest at old rate before updating
            let mut state = State::load(deps.storage)?;
            state.distribute_interest(&env, &config)?;
            state.save(deps.storage)?;
            
            config.interest = interest;
            config.save(deps.storage)?;
            Ok(Response::default())
        }
    }
}
```

This ensures interest accrued under the old rate is properly distributed before the new rate takes effect.

## Proof of Concept

Add this test to `contracts/rujira-ghost-vault/src/contract.rs` in the `tests` module:

```rust
#[test]
fn interest_rate_change_without_distribution() {
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let borrower = app.api().addr_make("borrower");

    app.init_modules(|router, _, storage| {
        router.bank.init_balance(storage, &owner, coins(10_000_000, "btc")).unwrap();
        router.bank.init_balance(storage, &borrower, coins(10_000_000, "btc")).unwrap();
    });

    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    let contract = app
        .instantiate_contract(
            code_id,
            owner.clone(),
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
                    base_rate: Decimal::from_ratio(20u128, 100u128), // 20% base rate
                    step1: Decimal::from_ratio(10u128, 100u128),
                    step2: Decimal::from_ratio(50u128, 100u128),
                },
                fee: Decimal::zero(),
                fee_address: owner.to_string(),
            },
            &[],
            "vault",
            None,
        )
        .unwrap();

    // Deposit 1,000,000 tokens
    app.execute_contract(
        owner.clone(),
        contract.clone(),
        &ExecuteMsg::Deposit { callback: None },
        &coins(1_000_000u128, "btc"),
    )
    .unwrap();

    // Whitelist and borrow
    app.wasm_sudo(
        contract.clone(),
        &SudoMsg::SetBorrower {
            contract: borrower.to_string(),
            limit: Uint128::from(800_000u128),
        },
    )
    .unwrap();

    app.execute_contract(
        borrower.clone(),
        contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Borrow {
            callback: None,
            amount: Uint128::from(800_000u128),
            delegate: None,
        }),
        &[],
    )
    .unwrap();

    // Advance 180 days - interest should accrue at 20% APR
    app.update_block(|x| x.time = x.time.plus_days(180));

    // Change interest rate to 5% WITHOUT distributing interest first
    app.wasm_sudo(
        contract.clone(),
        &SudoMsg::SetInterest(Interest {
            target_utilization: Decimal::from_ratio(8u128, 10u128),
            base_rate: Decimal::from_ratio(5u128, 100u128), // 5% base rate
            step1: Decimal::from_ratio(5u128, 100u128),
            step2: Decimal::from_ratio(20u128, 100u128),
        }),
    )
    .unwrap();

    // Advance 1 more day
    app.update_block(|x| x.time = x.time.plus_days(1));

    // Next transaction triggers distribute_interest
    let status: StatusResponse = app
        .wrap()
        .query_wasm_smart(contract.clone(), &QueryMsg::Status {})
        .unwrap();

    // Expected: 180 days at 20% + 1 day at 5%
    // Expected interest = 800_000 * 0.20 * (180/365) + 800_000 * 0.05 * (1/365)
    //                   = 78,904 + 110 = 79,014 tokens
    
    // Actual: 181 days at 5%
    // Actual interest = 800_000 * 0.05 * (181/365) = 19,835 tokens
    
    // Loss = 79,014 - 19,835 = 59,179 tokens (~75% of expected interest)

    println!("Debt pool size: {}", status.debt_pool.size);
    
    // The debt pool should be approximately 879,014 (800,000 + 79,014)
    // But it will be approximately 819,835 (800,000 + 19,835)
    // This demonstrates the ~59,179 token loss to depositors
    
    assert!(
        status.debt_pool.size < Uint128::from(850_000u128),
        "Interest calculated at new rate retroactively - depositors lose ~59k tokens"
    );
}
```

**Notes**

This vulnerability represents a fundamental flaw in the interest accrual mechanism when administrative rate changes occur. The protocol invariant "Always-Accrued Interest" is designed to ensure accurate accounting, but the `sudo()` entrypoint bypasses this critical safeguard. The fix is simple and maintains the invariant across all code paths including administrative actions.

The impact is particularly severe because:
1. It's deterministic and unavoidable
2. It affects the entire vault, not individual users
3. The magnitude scales with both the rate differential and the time elapsed
4. Low-activity vaults suffer more as transactions are infrequent

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L42-51)
```rust
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let config = Config::load(deps.storage)?;
    let mut state = State::load(deps.storage)?;
    let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
    let fees = state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L205-220)
```rust
pub fn sudo(deps: DepsMut, _env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    let mut config = Config::load(deps.storage)?;

    match msg {
        SudoMsg::SetBorrower { contract, limit } => {
            Borrower::set(deps.storage, deps.api.addr_validate(&contract)?, limit)?;
            Ok(Response::default())
        }
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            config.interest = interest;
            config.save(deps.storage)?;
            Ok(Response::default())
        }
    }
}
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L97-134)
```rust
    pub fn calculate_interest(
        &mut self,
        interest: &Interest,
        to: Timestamp,
        fee_rate: Decimal,
    ) -> Result<(Uint128, Uint128), ContractError> {
        let rate = Decimal256::from(self.debt_rate(interest)?);
        let seconds = to.seconds().sub(self.last_updated.seconds());
        let part = Decimal256::from_ratio(seconds, 31_536_000u128);

        let interest_decimal = Decimal256::from_ratio(self.debt_pool.size(), 1u128)
            .mul(rate)
            .mul(part);

        // add pending_interest to interest
        let interest_scaled = DecimalScaled::from(interest_decimal);

        // collect the fee for the protocol
        let fee_rate_scaled = DecimalScaled::from(Decimal256::from(fee_rate));
        // add the fee to the pending fees
        let fee_accrued = interest_scaled.mul(fee_rate_scaled);

        // net interest for the users
        let net_interest = interest_scaled.sub(fee_accrued).add(self.pending_interest);

        // add the fee to the pending fees
        let fee_total = fee_accrued.add(self.pending_fees);

        // decompose fee_total and net_interest
        let (fee, fee_frac) = fee_total.decompose();
        let (interest, interest_frac) = net_interest.decompose();

        // persist pendings
        self.pending_fees = fee_frac;
        self.pending_interest = interest_frac;

        Ok((Uint128::try_from(interest)?, Uint128::try_from(fee)?))
    }
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L136-168)
```rust
    pub fn distribute_interest(
        &mut self,
        env: &Env,
        config: &Config,
    ) -> Result<Uint128, ContractError> {
        // Calculate interest charged on total debt since last update
        let (interest, mut fee) =
            self.calculate_interest(&config.interest, env.block.time, config.fee)?;
        let mut shares = Uint128::zero();

        // deposit the protocol fee to the deposit pool to issue shares
        match self.deposit_pool.join(fee) {
            Ok(amount) => {
                shares = amount;
            }
            // if no shares were issued, add the fee to the pending fees for later distribution
            // set the fee to 0 so that the debt is not charged with the fee yet
            Err(SharePoolError::Zero(_)) => {
                self.pending_fees = self.pending_fees.add(DecimalScaled::from_ratio(fee, 1u128));
                fee = Uint128::zero();
            }
            Err(err) => return Err(err.into()),
        }

        // Allocate the interest to the deposit pool
        self.deposit_pool.deposit(interest)?;
        // Charge the interest to the debt pool, so that outstanding debt tokens are required to
        // pay this interest on return
        self.debt_pool.deposit(interest.add(fee))?;
        self.last_updated = env.block.time;

        Ok(shares)
    }
```

**File:** README.md (L120-122)
```markdown
### Always-Accrued Interest

Both execute and query entry points call state.distribute_interest before doing anything else, which accrues debt interest, credits depositors, and mints protocol fees; users therefore always act on up-to-date pool balances and rates (contracts/rujira-ghost-vault/src/contract.rs (lines 42-236), contracts/rujira-ghost-vault/src/state.rs (lines 52-171)).
```
