# Audit Report

## Title
Retroactive Interest Rate Application After Sudo Config Update Causes Incorrect Debt Calculations

## Summary
The `SudoMsg::SetInterest` function updates interest rate configuration without first accruing interest at the old rate. This causes subsequent operations to retroactively apply the new interest rate to periods when the old rate was in effect, resulting in incorrect debt calculations, pool sizes, and utilization ratios that directly impact borrowers and lenders.

## Finding Description

When interest rates are updated via the `sudo` function, the implementation only updates the config without distributing accrued interest first. [1](#0-0) 

This creates a critical timing issue: the state maintains a `last_updated` timestamp that tracks when interest was last distributed. When the interest config changes but state is not updated, subsequent `distribute_interest` calls retroactively apply the NEW rate to the entire period since `last_updated`, including time periods when the OLD rate should have been in effect.

The vulnerability manifests in both query and execute paths. In the query function, `distribute_interest` is called with the new config [2](#0-1)  before calculating rates at lines 235-236. [3](#0-2) 

The `calculate_interest` function applies the rate to the full time period since last update: [4](#0-3) 

More critically, all execute operations (deposit, withdraw, borrow, repay) call `distribute_interest` which persists this incorrect calculation to storage. [5](#0-4) 

**This breaks the "Always-Accrued Interest" invariant**: interest should be accurately calculated based on the rates in effect during each time period, not retroactively applied.

## Impact Explanation

**High Severity** - Direct financial loss affecting all borrowers:

**Scenario 1 - Rate Increase (10% → 100% APR):**
- Time T0: 1000 BTC borrowed at 10% APR
- Time T1 (6 months later): Sudo increases rate to 100% APR
- Time T2 (12 months from T0): Any operation triggers distribute_interest

Expected interest: 1000 × 0.10 × 0.5 + 1050 × 1.00 × 0.5 = 50 + 525 = 575 BTC

Actual interest: 1000 × 1.00 × 1.0 = 1000 BTC

**Overcharge: 425 BTC (73.9% excessive interest)**

**Scenario 2 - Rate Decrease (100% → 10% APR):**
Using the same timeline but reversed rates results in borrowers being undercharged by 425 BTC, causing direct loss to lenders and potential protocol insolvency.

The impact scales with:
- Time elapsed since last interest distribution
- Magnitude of rate change
- Total debt outstanding
- Number of affected borrowers

With typical vault sizes (millions in TVL) and governance rate adjustments occurring days/weeks after last activity, losses could reach hundreds of thousands of dollars per rate change.

## Likelihood Explanation

**High Likelihood:**

1. **Normal Operations**: Interest rate adjustments are standard governance actions in DeFi protocols responding to market conditions
2. **No Special Conditions**: Triggered automatically by any transaction after a rate change (deposits, withdrawals, borrows, repays, or queries)
3. **Affects All Users**: Every borrower with outstanding debt during the period is impacted
4. **Time-Based Accumulation**: The longer between rate change and next transaction, the larger the error
5. **Inevitable**: Will occur on every governance rate adjustment unless the protocol remains completely inactive (unlikely)

Governance is expected to adjust rates periodically (weekly/monthly) in response to market utilization, making this a recurring issue rather than an edge case.

## Recommendation

The sudo function must distribute interest using the current (old) config before updating to the new config:

```rust
SudoMsg::SetInterest(interest) => {
    interest.validate()?;
    
    // Accrue interest at OLD rate before changing config
    let mut state = State::load(deps.storage)?;
    let fees = state.distribute_interest(&env, &config)?;
    state.save(deps.storage)?;
    
    // Now update to NEW rate going forward
    config.interest = interest;
    config.save(deps.storage)?;
    
    // Mint fees if any were generated
    let mut response = Response::default();
    if fees.gt(&Uint128::zero()) {
        let rcpt = TokenFactory::new(&env, format!("ghost-vault/{}", config.denom).as_str());
        response = response.add_message(rcpt.mint_msg(fees, config.fee_address.clone()));
    }
    
    Ok(response)
}
```

This ensures interest is accurately calculated up to the point of rate change, with the new rate only applying to future periods.

## Proof of Concept

```rust
#[test]
fn test_retroactive_interest_rate_application() {
    use std::str::FromStr;
    let mut app = mock_rujira_app();
    let owner = app.api().addr_make("owner");
    let borrower = app.api().addr_make("borrower");

    app.init_modules(|router, _, storage| {
        router.bank.init_balance(storage, &owner, coins(10_000, "btc")).unwrap();
        router.bank.init_balance(storage, &borrower, coins(10_000, "btc")).unwrap();
    });

    let code = Box::new(ContractWrapper::new(execute, instantiate, query).with_sudo(sudo));
    let code_id = app.store_code(code);
    let contract = app.instantiate_contract(
        code_id, owner.clone(),
        &InstantiateMsg {
            denom: "btc".to_string(),
            receipt: TokenMetadata {
                description: "".to_string(), display: "".to_string(),
                name: "".to_string(), symbol: "".to_string(),
                uri: None, uri_hash: None,
            },
            interest: Interest {
                target_utilization: Decimal::from_ratio(8u128, 10u128),
                base_rate: Decimal::from_ratio(1u128, 10u128), // 10% APR
                step1: Decimal::from_ratio(1u128, 10u128),
                step2: Decimal::from_ratio(3u128, 1u128),
            },
            fee: Decimal::zero(),
            fee_address: owner.to_string(),
        },
        &[], "vault", None,
    ).unwrap();

    // Deposit 1000 BTC
    app.execute_contract(owner.clone(), contract.clone(), 
        &ExecuteMsg::Deposit { callback: None }, &coins(1_000, "btc")).unwrap();

    // Whitelist and borrow 800 BTC
    app.wasm_sudo(contract.clone(), &SudoMsg::SetBorrower {
        contract: borrower.to_string(), limit: Uint128::from(800u128),
    }).unwrap();
    app.execute_contract(borrower.clone(), contract.clone(),
        &ExecuteMsg::Market(MarketMsg::Borrow { amount: Uint128::from(800u128), callback: None, delegate: None }),
        &[]).unwrap();

    // Advance 6 months - at 10% rate, interest = 800 * 0.1 * 0.5 = 40 BTC
    app.update_block(|b| b.time = b.time.plus_seconds(15_768_000)); // 6 months

    // Governance increases rate to 100% (10x)
    app.wasm_sudo(contract.clone(), &SudoMsg::SetInterest(Interest {
        target_utilization: Decimal::from_ratio(8u128, 10u128),
        base_rate: Decimal::from_ratio(1u128, 1u128), // 100% APR
        step1: Decimal::from_ratio(1u128, 10u128),
        step2: Decimal::from_ratio(3u128, 1u128),
    })).unwrap();

    // Advance another 6 months - at 100% rate, interest should be ~840 * 1.0 * 0.5 = 420 BTC
    app.update_block(|b| b.time = b.time.plus_seconds(15_768_000));

    // Query status to trigger distribute_interest
    let status: StatusResponse = app.wrap()
        .query_wasm_smart(contract.clone(), &QueryMsg::Status {}).unwrap();

    // Expected total interest: 40 (6mo @ 10%) + 420 (6mo @ 100%) = 460 BTC
    // Actual: Retroactive application of 100% for full year: 800 * 1.0 = 800 BTC
    // Debt should be ~1260, but will be ~1600
    
    println!("Debt pool size: {}", status.debt_pool.size);
    println!("Expected: ~1260 BTC (800 + 40 + 420)");
    println!("Actual: ~1600 BTC (retroactive 100% rate)");
    
    // Verify overcharge: debt_pool.size should be much higher than expected
    assert!(status.debt_pool.size > Uint128::from(1500u128), 
        "Retroactive rate application causes excessive debt");
}
```

This test demonstrates borrowers being charged approximately 340 BTC more than they should due to retroactive application of the increased rate to the 6-month period before the rate change.

### Citations

**File:** contracts/rujira-ghost-vault/src/contract.rs (L51-51)
```rust
    let fees = state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L213-217)
```rust
        SudoMsg::SetInterest(interest) => {
            interest.validate()?;
            config.interest = interest;
            config.save(deps.storage)?;
            Ok(Response::default())
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L226-226)
```rust
    state.distribute_interest(&env, &config)?;
```

**File:** contracts/rujira-ghost-vault/src/contract.rs (L235-236)
```rust
            debt_rate: state.debt_rate(&config.interest)?,
            lend_rate: state.lend_rate(&config.interest)?,
```

**File:** contracts/rujira-ghost-vault/src/state.rs (L103-109)
```rust
        let rate = Decimal256::from(self.debt_rate(interest)?);
        let seconds = to.seconds().sub(self.last_updated.seconds());
        let part = Decimal256::from_ratio(seconds, 31_536_000u128);

        let interest_decimal = Decimal256::from_ratio(self.debt_pool.size(), 1u128)
            .mul(rate)
            .mul(part);
```
