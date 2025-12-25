# NoVulnerability found for this question.

## Rationale for Rejection

This security claim fails **Phase 1, Section B: Threat Model Violations**.

### Critical Flaw in the Claim

The vulnerability premise states: *"When the THORChain oracle reports zero value for collateral assets due to oracle failures or manipulation..."*

This explicitly requires the oracle to malfunction or be compromised, which violates the stated threat model:

> "Note: THORChain oracle providers and Rujira Deployer Multisig are trusted roles."

The validation framework explicitly disqualifies:
> "❌ Requires THORChain oracle manipulation or compromise (oracles are trusted)"

### Technical Analysis of the Code Path

When examining the actual code behavior:

**1. Oracle Query Error Handling:** [1](#0-0) 

The `?` operator on line 302 **propagates errors** - it does not convert them to zero. If the oracle lacks pricing data, an `OraclePriceError` is returned, causing `CreditAccount::load()` to fail entirely. [2](#0-1) 

When `OraclePrice::load()` cannot find pricing data, it returns `TryFromOraclePriceError::NotFound`: [3](#0-2) 

**2. The Only Zero-Value Scenario:**

The filtering on line 302 only executes when:
- The oracle **successfully returns** a price response
- That price **equals zero** (or rounds to zero)

For an asset with "real market value $30,000" (per the claim's example) to be valued at $0, the oracle must return incorrect data. This is either:
- **Oracle malfunction** (not behaving as a trusted component should)
- **Oracle manipulation** (explicit compromise)

Both scenarios violate the trust assumptions.

**3. The "New Asset Listings" Argument Fails:**

The claim suggests: *"New asset listings before oracle integration (high likelihood)"*

This scenario does not work because:
- If oracle lacks pricing → error returned → account loading fails
- Liquidation cannot proceed (checked at line 76): [4](#0-3) 

### Conclusion

The vulnerability **requires a trusted component (THORChain oracle) to provide incorrect data**, which is outside the security model. The protocol correctly handles missing oracle data by returning errors. The only way for collateral to be filtered with zero value is if the oracle returns bad data, constituting a trust assumption violation.

This is not a protocol vulnerability - it's a dependency on trusted infrastructure behaving correctly, which is an explicit assumption of the security model.

### Citations

**File:** contracts/rujira-ghost-credit/src/account.rs (L302-304)
```rust
            if item.value_usd(deps.querier)?.is_zero() {
                continue;
            }
```

**File:** packages/rujira-rs/src/query/oracle_price.rs (L40-41)
```rust
            None => Err(TryFromOraclePriceError::NotFound {}),
        }
```

**File:** packages/rujira-rs/src/query/oracle_price.rs (L60-67)
```rust
    pub fn load(q: QuerierWrapper, symbol: &str) -> Result<Self, OraclePriceError> {
        let req = QueryOraclePriceRequest {
            height: "0".to_string(),
            symbol: symbol.to_owned(),
        };
        let res = QueryOraclePriceResponse::get(q, req)?;
        Ok(OraclePrice::try_from(res)?)
    }
```

**File:** contracts/rujira-ghost-credit/src/contract.rs (L74-76)
```rust
            let account =
                CreditAccount::load(deps.as_ref(), &config, &ca, deps.api.addr_validate(&addr)?)?;
            account.check_unsafe(&config.liquidation_threshold)?;
```
