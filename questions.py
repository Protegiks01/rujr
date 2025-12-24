import json

BASE_URL = "https://deepwiki.com/code-423n4/2025-12-rujira"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator = [
    "contracts/rujira-account/src/lib.rs",
    "contracts/rujira-account/src/contract.rs",
    "contracts/rujira-account/src/execute.rs",
    "contracts/rujira-account/src/error.rs",
    "contracts/rujira-account/src/state.rs",
    "contracts/rujira-ghost-credit/src/lib.rs",
    "contracts/rujira-ghost-credit/src/account.rs",
    "contracts/rujira-ghost-credit/src/config.rs",
    "contracts/rujira-ghost-credit/src/contract.rs",
    "contracts/rujira-ghost-credit/src/error.rs",
    "contracts/rujira-ghost-credit/src/events.rs",
    "contracts/rujira-ghost-credit/src/state.rs",
    "contracts/rujira-ghost-vault/src/lib.rs",
    "contracts/rujira-ghost-vault/src/borrowers.rs",
    "contracts/rujira-ghost-vault/src/config.rs",
    "contracts/rujira-ghost-vault/src/contract.rs",
    "contracts/rujira-ghost-vault/src/error.rs",
    "contracts/rujira-ghost-vault/src/events.rs",
    "contracts/rujira-ghost-vault/src/state.rs"
]


def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for Rujira Protocol.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""  
You are an **Elite DeFi Security Auditor** specializing in   
overcollateralized lending protocols, cross-chain asset management, oracle   
manipulation resistance, and liquidation mechanisms. Your task is to analyze   
the **Rujira Protocol** codebase—a CosmWasm-based lending and borrowing system   
built on THORChain featuring secured assets, multi-collateral credit accounts,   
and permissionless liquidations—through the lens of this single security question:   
  
**Security Question (scope for this run):** {question}  
  
**RUJIRA PROTOCOL CONTEXT:**  
  
**Architecture**: Rujira enables overcollateralized borrowing of THORChain secured   
assets through a three-contract system. Users deposit collateral into credit accounts   
(`rujira-account`), borrow from lending vaults (`rujira-ghost-vault`), and all operations   
are orchestrated by a registry contract (`rujira-ghost-credit`). The protocol maintains   
solvency through dynamic LTV calculations, collateral ratio haircuts, and   
permissionless liquidation mechanisms.  
  
Think in invariant   
Check every logic entry that could affect the protocol base on the question provided   
Look at the exact file provided and other places also if it can cause a severe vuln   
Think in an elite way becasue there is always a logic vuln that could occur   
  
**Key Components**:   
  
* **Credit Registry**: `rujira-ghost-credit/src/contract.rs` (main orchestrator   
  with account creation, LTV enforcement, liquidation triggers),   
  `rujira-ghost-credit/src/account.rs` (account validation and LTV calculations),   
  `rujira-ghost-credit/src/config.rs` (protocol parameters and validation)  
  
* **Lending Vaults**: `rujira-ghost-vault/src/contract.rs` (vault operations,   
  interest distribution), `rujira-ghost-vault/src/state.rs` (share accounting,   
  interest accrual), `rujira-ghost-vault/src/borrowers.rs` (borrower limits   
  and authorization)  
  
* **Individual Accounts**: `rujira-account/src/contract.rs` (sudo-only access   
  pattern, isolated accounting), `rujira-account/src/execute.rs` (message   
  forwarding and execution)  
  
**Files in Scope**: All contracts in `contracts/rujira-account/src/`,   
`contracts/rujira-ghost-credit/src/`, and `contracts/rujira-ghost-vault/src/`   
directories. Test files are **out of scope** for vulnerability analysis   
but may be referenced for understanding expected behavior.  
  
**CRITICAL INVARIANTS (derived from protocol specification and code):**  
  
1. **Owner-Gated Accounts**: Only `account.owner` can initiate operations via   
   `ExecuteMsg::Account`. This ensures debt creation and collateral movements   
   are bound to the NFT-like ownership model.  
  
2. **Post-Adjustment LTV Check**: After any owner operation, `adjusted_ltv` must   
   be `< adjustment_threshold`. If exceeded, the transaction fails to prevent   
   unsafe account states.  
  
3. **Safe Liquidation Outcomes**: Liquidations only trigger when   
   `adjusted_ltv >= liquidation_threshold` and must stop before over-selling   
   collateral, respecting user preferences and max slip limits.  
  
4. **Whitelisted Vault Access**: Registry only routes to vaults listed in   
   `collateral_ratios`, preventing rogue contracts from being used as debt sources.  
  
5. **Bounded Config Values**: All configuration changes validated via   
   `Config::validate`, enforcing fee caps, ratio constraints, and threshold ordering.  
  
6. **Fee-First Liquidation Repay**: Protocol and liquidator fees extracted before   
   debt repayment, ensuring fees are never minted without real debt repayment.  
  
7. **Admin-Only Accounts**: `rujira-account` instances only accept `sudo` calls   
   from registry, maintaining strict access control over account operations.  
  
8. **Governance-Whitelisted Borrowers**: Only pre-approved contracts via   
   `SudoMsg::SetBorrower` can borrow from vaults, preventing unauthorized debt creation.  
  
9. **Borrow Limit Enforcement**: Each borrower has a maximum USD value they can   
   borrow, preventing systemic over-leverage.  
  
10. **Always-Accrued Interest**: `distribute_interest()` called before all operations,   
    ensuring accurate accounting and preventing stale data manipulation.  
  
**YOUR INVESTIGATION MISSION:**  
  
Accept the premise of the security question and explore **all** relevant   
code paths, data structures, state transitions, and cross-contract   
interactions related to it. Do not settle for surface observations—trace   
execution flows through account creation → collateral deposit → borrowing   
→ LTV validation → liquidation flows.  
  
Your goal is to find **one** concrete, exploitable vulnerability tied to   
the question that an attacker, liquidator, or malicious user could exploit.   
Focus on:   
  
* Business-logic flaws (incorrect validation, missing checks)  
* Mathematical errors (overflow, underflow, precision loss in LTV calculations)  
* Race conditions (concurrent account operations, share accounting)  
* Oracle manipulation (THORChain oracle price feeds)  
* Collateral calculation bugs (collateral ratios, LTV computations)  
* Liquidation vulnerabilities (premature liquidation, fee extraction)  
* Interest accrual manipulation (distribution calculations, rate determination)  
* Access control bypasses (sudo pattern violations, owner validation)  
* Cross-contract interaction bugs (registry-vault-account communication)  
* Asset accounting errors (share price manipulation, supply inconsistencies)  
  
**ATTACK SURFACE EXPLORATION:**  
  
1. **Account Operations** (`rujira-ghost-credit/src/contract.rs`, `rujira-ghost-credit/src/account.rs`):  
   - Owner validation bypasses in `ExecuteMsg::Account`  
   - LTV calculation errors during collateral/borrow operations  
   - Race conditions between account state updates and LTV checks  
   - Collateral ratio manipulation through asset valuation bugs  
   - Account transfer vulnerabilities affecting ownership model  
  
2. **Liquidation Mechanism** (`rujira-ghost-credit/src/contract.rs`):  
   - Premature liquidation through oracle manipulation  
   - Liquidation fee extraction exceeding protocol limits  
   - Partial liquidation leaving residual debt positions  
   - Liquidatee preference order manipulation  
   - Max slip limit bypasses enabling over-collateralization  
  
3. **Vault Operations** (`rujira-ghost-vault/src/contract.rs`, `rujira-ghost-vault/src/state.rs`):  
   - Share price manipulation through accounting errors  
   - Interest distribution bugs enabling unlimited minting  
   - Borrower limit bypasses through delegate borrowing  
   - Deposit/withdrawal accounting inconsistencies  
   - Protocol fee calculation errors  
  
4. **Access Control** (`rujira-account/src/contract.rs`, `rujira-ghost-vault/src/borrowers.rs`):  
   - Sudo pattern violations enabling unauthorized account control  
   - Borrower whitelist bypasses allowing unauthorized debt creation  
   - Admin privilege escalation through configuration manipulation  
   - Cross-contract authorization failures  
  
5. **Oracle Integration** (THORChain oracle usage):  
   - Price manipulation through oracle feed attacks  
   - Stale oracle data exploitation in LTV calculations  
   - Cross-chain price inconsistencies enabling arbitrage  
   - Oracle failure handling during liquidations  
  
6. **Mathematical Operations** (LTV, interest, share calculations):  
   - Precision loss in collateral-to-debt conversions  
   - Overflow/underflow in share supply calculations  
   - Rounding errors in interest distribution  
   - Collateral ratio computation bugs  
  
**RUJIRA-SPECIFIC ATTACK VECTORS:**  
  
- **LTV Calculation Manipulation**: Can attackers manipulate collateral valuations   
  or debt calculations to bypass `adjustment_threshold` and create undercollateralized positions?  
- **Liquidation Race Conditions**: Can timing attacks between oracle updates and   
  liquidation triggers enable profitable liquidations at manipulated prices?  
- **Share Price Exploitation**: Can attackers manipulate share price calculations   
  in vaults to drain assets or extract protocol fees?  
- **Access Control Bypass**: Can attackers circumvent the sudo pattern or owner   
  validation to gain unauthorized control over credit accounts?  
- **Interest Accrual Bugs**: Can interest calculation errors enable unlimited   
  asset minting or interest avoidance through timing attacks?  
- **Cross-Contract State Inconsistencies**: Can state synchronization issues between   
  registry, vaults, and accounts create exploitable arbitrage opportunities?  
- **Collateral Ratio Haircut Bypass**: Can attackers exploit collateral ratio   
  calculations to over-value volatile assets and increase borrowing capacity?  
- **Liquidation Fee Extraction**: Can liquidators extract fees exceeding protocol   
  limits through calculation errors or state manipulation?  
- **Oracle Manipulation**: Can THORChain oracle manipulation enable profitable   
  liquidations or borrowing attacks?  
- **Account Ownership Transfer Bugs**: Can account transfer mechanisms be exploited   
  to bypass ownership controls or facilitate collateral theft?  
  
**TRUST MODEL:**  
  
**Trusted Roles**: THORChain oracle providers, Rujira Deployer Multisig, THORChain   
node operators. Do **not** assume these actors behave maliciously unless the   
question explicitly explores compromised oracle or governance scenarios.  
  
**Untrusted Actors**: Any user creating accounts, borrowing funds, liquidating   
positions, or attempting price manipulation. Focus your analysis on bugs   
exploitable by untrusted actors without requiring oracle compromise or   
governance collusion.  
  
**KNOWN ISSUES / EXCLUSIONS:**  
  
- Cryptographic primitives (CosmWasm crypto functions) are assumed secure  
- THORChain network security (assumed resistant to 51% attacks)  
- Oracle data accuracy (oracles are trusted to provide correct data)  
- Network-level attacks (DDoS, BGP hijacking, DNS poisoning)  
- CosmWasm runtime bugs unrelated to Rujira code  
- Social engineering, phishing, or key theft  
- Gas optimization, code style, missing comments  
- Precision loss <0.01% in fee calculations  
- Test file issues (tests are out of scope)  
- Market risk (price movements) unless caused by protocol bugs  
- MEV or front-running attacks unless enabled by protocol vulnerabilities  
  
**VALID IMPACT CATEGORIES (Code4rena Bug Bounty):**  
  
**Critical Severity**:  
- Direct loss of funds (theft of user collateral or protocol assets)  
- Permanent freezing of funds (fix requires protocol redeployment)  
- Protocol insolvency leading to systemic loss  
  
**High Severity**:  
- Temporary freezing of funds with economic loss  
- Systemic undercollateralization risks  
- Widespread liquidations due to protocol bugs  
  
**Medium Severity**:  
- Economic manipulation benefiting attackers  
- State inconsistencies requiring manual intervention  
- Interest or fee calculation errors  
- DoS vulnerabilities affecting core functionality  
  
**Low/QA (out of scope)**:  
- Minor precision loss (<0.01%)  
- Gas inefficiencies  
- Event emission or logging issues  
- Non-critical edge cases with no financial impact  
  
**OUTPUT REQUIREMENTS:**  
  
If you discover a valid vulnerability related to the security question,   
produce a **full report** following the format below. Your report must include:   
- Exact file paths and function names  
- Code quotations (actual snippets from the in-scope contracts)  
- Step-by-step exploitation path with realistic parameters  
- Clear explanation of which invariant is broken  
- Impact quantification (fund loss amount, collateral affected)  
- Likelihood assessment (attacker profile, preconditions, complexity)  
- Concrete recommendation with code fix  
- Proof of Concept (Rust test demonstrating the exploit)  
  
If **no** valid vulnerability emerges after thorough investigation, state exactly:   
`#NoVulnerability found for this question.`  
  
**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with   
clear attack paths and realistic impact count.  
  
**Do not** report:   
- Known issues from previous Halborn audits  
- Out-of-scope problems (test files, CosmWasm bugs, crypto primitive breaks)  
- Theoretical vulnerabilities without clear attack path and PoC  
- Issues requiring trusted roles to behave maliciously  
- Minor optimizations, style issues, or low-severity findings  
  
**Focus on one high-quality finding** rather than multiple weak claims.  
  
**VALIDATION CHECKLIST (Before Reporting):**  
- [ ] Vulnerability lies within one of the in-scope contracts (not test/)  
- [ ] Exploitable by unprivileged attacker (no oracle/governance collusion required)  
- [ ] Attack path is realistic with correct data types and feasible parameters  
- [ ] Impact meets Critical, High, or Medium severity per Code4rena scope  
- [ ] PoC can be implemented as Rust test or transaction sequence  
- [ ] Issue breaks at least one documented invariant  
- [ ] Not a known exclusion from Halborn audits  
- [ ] Clear financial harm, collateral loss, or state divergence demonstrated  
  
---  
  
**AUDIT REPORT FORMAT** (if vulnerability found):  
  
Audit Report  
  
## Title   
The Title Of the Report   
  
## Summary  
A short summary of the issue, keep it brief.  
  
## Finding Description  
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.  
  
Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.  
  
## Impact Explanation  
Elaborate on why you've chosen a particular impact assessment.  
  
## Likelihood Explanation  
Explain how likely this is to occur and why.  
  
## Recommendation  
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.  
  
## Proof of Concept  
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.  
Very important the test function using their test must be provided in here and pls it must be able to compile and run successfully  
  
**Remember**: False positives harm credibility more than missed findings.  Assume claims are invalid until overwhelming evidence proves otherwise.  
  
**Now perform STRICT validation of the claim above.**  
  
**Output ONLY:**  
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format  
- `#NoVulnerability found for this question.` (if **any** check fails)  
  
**Be ruthlessly skeptical.  The bar for validity is EXTREMELY valid.**  
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for Rujira Protocol security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""
You are an **Elite DeFi Security Judge** with deep expertise in overcollateralized lending protocols, CosmWasm smart contracts, THORChain integration, and Code4rena bug bounty validation. Your ONLY task is **ruthless technical validation** of security claims against the Rujira codebase.

Note: THORChain oracle providers and Rujira Deployer Multisig are trusted roles.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **RUJIRA PROTOCOL VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if **ANY** apply:

#### **A. Scope Violations**
- ❌ Affects files **not** in the three in-scope contract directories
- ❌ Targets any file under test directories (`*.test.*`, `tests/`) - tests are out of scope
- ❌ Claims about documentation, comments, code style, or logging (not security issues)
- ❌ Focuses on out-of-scope components: rujira-bow, rujira-fin, rujira-thorchain-swap, rujira-mint, rujira-pilot, rujira-staking, rujira-revenue

**In-Scope Files (3 contracts):**
- **rujira-account**: `contracts/rujira-account/src/**/*.rs` (sudo pattern, isolated accounting)
- **rujira-ghost-credit**: `contracts/rujira-ghost-credit/src/**/*.rs` (registry, LTV enforcement, liquidations)
- **rujira-ghost-vault**: `contracts/rujira-ghost-vault/src/**/*.rs` (lending vaults, interest distribution)

**Verify**: Check that every file path cited in the report matches exactly one of the in-scope contracts.

#### **B. Threat Model Violations**
- ❌ Requires THORChain oracle manipulation or compromise (oracles are trusted)
- ❌ Assumes compromised Rujira Deployer Multisig (multisig is trusted role)
- ❌ Needs THORChain node operators to act maliciously (node operators are trusted)
- ❌ Requires attacker to compromise CosmWasm runtime or blockchain consensus
- ❌ Assumes cryptographic primitives (CosmWasm crypto functions) are broken
- ❌ Depends on network-level attacks: DDoS, BGP hijacking, DNS poisoning
- ❌ Relies on social engineering, phishing, key theft, or user operational security failures

**Trusted Roles**: THORChain oracle providers provide price feeds; Rujira Deployer Multisig controls protocol parameters; THORChain node operators can pause contracts. Do **not** assume these actors behave maliciously.

**Untrusted Actors**: Any user creating accounts, borrowing funds, liquidating positions, or attempting manipulation.

#### **C. Known Issues / Accepted Risks** (from Halborn audits)
- ❌ Any finding already mentioned in Halborn audit reports
- ❌ Liquidations requiring off-chain triggering (by design, permissionless)
- ❌ Market risk from normal price movements (not protocol bugs)
- ❌ THORChain network-level issues or secured asset risks
- ❌ Precision loss <0.01% in calculations
- ❌ Gas/fee optimization issues without security impact

#### **D. Non-Security Issues**
- ❌ Gas optimizations, performance improvements, or micro-optimizations
- ❌ Code style, naming conventions, or refactoring suggestions
- ❌ Missing events, logs, error messages, or better user experience
- ❌ Documentation improvements, README updates, or comment additions
- ❌ "Best practices" recommendations with no concrete exploit scenario
- ❌ Input validation preventing honest user mistakes unless it enables theft
- ❌ Minor precision errors with negligible financial impact (<0.01%)

#### **E. Invalid Exploit Scenarios**
- ❌ Requires impossible inputs: negative amounts, invalid addresses, unrealistic prices
- ❌ Cannot be triggered through any realistic ExecuteMsg or SudoMsg call
- ❌ Depends on calling internal functions not exposed through any public API
- ❌ Relies on race conditions prevented by atomic operations or state checks
- ❌ Needs multiple coordinated transactions with no economic incentive
- ❌ Requires attacker to already possess the collateral they seek to steal
- ❌ Depends on block timestamp manipulation beyond reasonable bounds

### **PHASE 2: RUJIRA-SPECIFIC DEEP CODE VALIDATION**

#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH LENDING ARCHITECTURE**

**Rujira Flow Patterns:**

1. **Account Creation Flow**:
   User calls `rujira-ghost-credit::ExecuteMsg::CreateAccount` → creates new `rujira-account` instance → registry set as admin → sudo-only access established

2. **Collateral Deposit Flow**:
   User sends tokens to account → calls `ExecuteMsg::Account(AccountMsg::Deposit)` → registry validates ownership → sudo call to account → tokens held in isolated accounting

3. **Borrowing Flow**:
   User calls `ExecuteMsg::Account(AccountMsg::Borrow)` → registry validates ownership & LTV → sudo call to account → account calls `BorrowerMsg::Borrow` on vault → vault checks borrower whitelist & limits → tokens transferred to account

4. **Liquidation Flow**:
   Liquidator calls `ExecuteMsg::Liquidate` → registry checks `adjusted_ltv >= liquidation_threshold` → calculates fees & repayment → sudo calls to close positions → liquidator receives bonus

For each claim, reconstruct the entire execution path:

1. **Identify Entry Point**: Which user-facing function is called? (`ExecuteMsg::Account`, `ExecuteMsg::Liquidate`, etc.)
2. **Follow Internal Calls**: Trace through all function calls, including:
   - Ownership validation in `rujira-ghost-credit`
   - LTV calculations in `account.rs`
   - Sudo forwarding to `rujira-account`
   - Vault operations in `rujira-ghost-vault`
3. **State Before Exploit**: Document initial state (collateral balances, debt, LTV ratios)
4. **State Transitions**: Enumerate all changes (collateral movements, debt updates, share minting/burning)
5. **Check Protections**: Verify if ownership checks, LTV validation, or mathematical constraints prevent the exploit
6. **Final State**: Show how the exploit results in unauthorized state (collateral loss, undercollateralization, share manipulation)

#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**

For **each assertion** in the report, demand:

**✅ Required Evidence:**
- Exact file path and line numbers (e.g., `rujira-ghost-credit/src/account.rs:152-191`) within in-scope contracts
- Direct Rust code quotes showing the vulnerable logic
- Call traces with actual parameter values demonstrating how execution reaches the vulnerable line
- Calculations showing how collateral, debt, or LTV ratios change incorrectly
- References to specific invariant violations

**🚩 RED FLAGS (indicate INVALID):**

1. **"Missing Validation" Claims**:
   - ❌ Invalid unless report shows input bypasses *all* validation layers:
     - `ExecuteMsg::Account` ownership checks in `rujira-ghost-credit`
     - LTV validation in `account.rs`
     - Vault borrower whitelist checks
     - Sudo pattern restrictions in `rujira-account`
   - ✅ Valid if a specific input type genuinely has no validation path

2. **"LTV Calculation" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `adjusted_ltv` calculation produces incorrect values
     - Attacker can bypass `adjustment_threshold` or `liquidation_threshold`
     - Specific mathematical error in collateral ratio computation
   - ✅ Valid if LTV calculations can be manipulated for undercollateralization

3. **"Share Price Manipulation" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `totalAssets()` or `totalSupply()` can be manipulated in vault
     - Share price decreases unexpectedly allowing asset drainage
     - Attacker can extract value through share accounting errors
   - ✅ Valid if share accounting enables fund extraction

4. **"Access Control Bypass" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Sudo pattern can be circumvented in `rujira-account`
     - Ownership validation can be bypassed in `rujira-ghost-credit`
     - Borrower whitelist can be bypassed in vault
   - ✅ Valid if access controls can be circumvented

5. **"Liquidation Vulnerability" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Liquidation can be triggered prematurely or incorrectly
     - Fee extraction exceeds protocol limits
     - Liquidation process leaves residual debt or over-sells collateral
   - ✅ Valid if liquidation mechanism can be exploited

6. **"Interest Accrual Bugs" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `distribute_interest()` miscalculates interest or shares
     - Interest index fails to update correctly
     - Attacker can mint unlimited shares through interest manipulation
   - ✅ Valid if interest calculations enable fund extraction

7. **"Collateral Ratio" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Collateral ratio haircuts can be bypassed
     - Asset valuation can be manipulated for higher borrowing capacity
     - Cross-collateral calculations are incorrect
   - ✅ Valid if collateral calculations enable undercollateralization

8. **"Mathematical Overflow" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Specific arithmetic operation overflows/underflows
     - Overflow causes incorrect LTV or share calculations
     - Attacker can exploit overflow for fund theft
   - ✅ Valid if mathematical errors enable fund loss

#### **Step 3: CROSS-REFERENCE WITH TEST SUITE**

Rujira's test suite includes comprehensive tests (out of scope but informative). Ask:

1. **Existing Coverage**: Do current tests handle the scenario? Check tests like:
   - `rujira-ghost-credit/src/tests/contract.rs` - account lifecycle
   - Vault tests for interest distribution and borrowing
   - Account tests for sudo pattern and isolation

2. **Test Gaps**: Is there an obvious gap that would allow the exploit? If scenario is untested, suggest adding test but do **not** assume vulnerability.

3. **Invariant Tests**: Would existing invariant checks catch the bug? Tests verify:
   - Owner-gated account operations
   - Post-adjustment LTV checks
   - Safe liquidation outcomes
   - Always-accrued interest

4. **PoC Feasibility**: Can the report's PoC be implemented as a Rust test using existing contracts without modifying core code?

**Test Case Realism Check**: PoCs must use realistic account structures, valid collateral amounts, and respect protocol constraints.

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**

#### **Impact Must Be CONCRETE and ALIGN WITH CODE4RENA SCOPE**

**✅ Valid CRITICAL Severity Impacts (per Code4rena scope):**

1. **Direct Loss of Funds (Critical)**:
   - Theft of user collateral from credit accounts
   - Theft of vault assets through share manipulation
   - Unauthorized borrowing from vaults
   - Collateral drainage through mathematical exploits
   - Example: "Share price manipulation allows attacker to drain 1000 USDC from vault"

2. **Protocol Insolvency (Critical)**:
   - Systemic undercollateralization causing protocol-wide losses
   - LTV calculation errors enabling mass undercollateralization
   - Share supply overflow preventing all operations
   - Example: "LTV calculation bug allows all accounts to become undercollateralized simultaneously"

3. **Permanent Freezing of Funds (Critical)**:
   - Funds locked with no transaction able to unlock them
   - Account bricking preventing collateral withdrawal
   - Share supply overflow preventing withdrawals
   - Example: "Account creation bug locks 500 BTC collateral permanently"

**✅ Valid HIGH Severity Impacts:**

4. **Temporary Freezing with Economic Loss (High)**:
   - Funds temporarily frozen causing economic damage
   - Widespread liquidations due to protocol bugs
   - Systemic undercollateralization risks
   - Example: "Liquidation bug causes 100 accounts to be liquidated unnecessarily"

**✅ Valid MEDIUM Severity Impacts:**

5. **Economic Manipulation (Medium)**:
   - Interest rate manipulation benefiting attackers
   - Liquidation bonus extraction beyond intended amounts
   - State inconsistencies requiring manual intervention
   - Example: "Interest accrual bug allows attacker to extract 10 ETH in excess interest"

6. **State Inconsistencies (Medium)**:
   - Interest or fee calculation errors
   - DoS vulnerabilities affecting core functionality
   - LTV calculation inconsistencies
   - Example: "LTV calculation bug causes 5% error in collateral requirements"

**❌ Invalid "Impacts":**

- User withdraws their own collateral (normal protocol operation)
- Attacker loses their own funds through self-draining (not an exploit)
- Theoretical cryptographic weaknesses without practical exploit
- General market risk (price movements) unless caused by protocol bugs
- "Could be problematic if..." statements without concrete exploit path
- Minor fee overpayment or underpayment (<0.1% of transaction value)
- Precision loss <0.01% across reasonable transaction volumes

#### **Likelihood Reality Check**

Assess exploit feasibility:

1. **Attacker Profile**:
   - Any user with THORChain secured assets to deposit? ✅ Likely
   - Liquidator monitoring for undercollateralized accounts? ✅ Possible
   - Attacker with ability to manipulate THORChain oracles? ❌ Impossible (trusted role)
   - Compromised Rujira Deployer Multisig? ❌ Impossible (trusted role)

2. **Preconditions**:
   - Normal market operation? ✅ High likelihood
   - High vault utilization? ✅ Possible during volatile periods
   - Specific account structure (multiple collateral types)? ✅ Attacker-controlled
   - Specific oracle state (price movements)? ✅ Attacker can time submission
   - Network congestion or high gas prices? ✅ Possible but not required

3. **Execution Complexity**:
   - Single ExecuteMsg call? ✅ Simple
   - Multiple coordinated transactions? ✅ Moderate (attacker controls)
   - Complex account with multiple collateral types? ✅ Attacker can create
   - Requires precise timing or front-running? ⚠️ Higher complexity
   - Requires mathematical precision? ✅ Attacker can calculate

4. **Economic Cost**:
   - Collateral deposit required? ✅ Attacker-determined (can be minimal)
   - Gas costs for transactions? ✅ Moderate
   - Potential profit vs. cost? ✅ Must be positive for valid exploit
   - Liquidation capital required? ✅ Varies by opportunity

5. **Combined Probability**:
   - Multiply probabilities of all conditions
   - If resulting likelihood <0.1% with no economic incentive → Invalid
   - If exploit is profitable and feasible → Valid

### **PHASE 4: FINAL VALIDATION CHECKLIST**

Before accepting any vulnerability, verify:

1. **Scope Compliance**: Vulnerability affects only the 3 in-scope contracts
2. **Not Known Issue**: Check against Halborn audit reports
3. **Trust Model**: Exploit doesn't require THORChain oracle or Deployer Multisig compromise
4. **Impact Severity**: Meets Critical/High/Medium per Code4rena scope
5. **Economic Incentive**: Attack must be profitable for attacker
6. **Technical Feasibility**: Exploit can be implemented without protocol modifications
7. **Invariant Violation**: Clearly breaks one of the 10 documented Rujira invariants
8. **PoC Completeness**: Rust test runs successfully against unmodified codebase

**Remember**: False positives harm credibility. Assume claims are invalid until overwhelming evidence proves otherwise.

---

**AUDIT REPORT FORMAT** (if vulnerability found):  
  
Audit Report  
  
## Title   
The Title Of the Report   
  
## Summary  
A short summary of the issue, keep it brief.  
  
## Finding Description  
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.  
  
Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.  
  
## Impact Explanation  
Elaborate on why you've chosen a particular impact assessment.  
  
## Likelihood Explanation  
Explain how likely this is to occur and why.  
  
## Recommendation  
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.  
  
## Proof of Concept  
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.  
Very important the test function using their test must be provided in here and pls it must be able to compile and run successfully  
  
**Remember**: False positives harm credibility more than missed findings.  Assume claims are invalid until overwhelming evidence proves otherwise.  
  
**Now perform STRICT validation of the claim above.**  
  
**Output ONLY:**  
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format  
- `#NoVulnerability found for this question.` (if **any** check fails)  very important 
  
**Be ruthlessly skeptical.  The bar for validity is EXTREMELY valid.**  
"""
    return prompt


def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Rujira protocol file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "contracts/rujira-ghost-credit/src/contract.rs")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""
# **Generate 150+ Targeted Security Audit Questions for Rujira Protocol**

## **Context**

The target project is **Rujira**, an overcollateralized lending protocol built on THORChain using CosmWasm. The protocol enables users to deposit THORChain secured assets as collateral and borrow against them through a sophisticated three-contract system. Unlike traditional lending protocols, Rujira employs isolated accounting through individual `rujira-account` instances, orchestrated by a `rujira-ghost-credit` registry, with assets held in `rujira-ghost-vault` lending pools. The protocol maintains solvency through dynamic LTV calculations, collateral ratio haircuts, and permissionless liquidation mechanisms, while supporting complex features like multi-collateral accounts, cross-collateralization, and adaptive interest rates.

Rujira's architecture includes critical components for account creation, collateral management, borrowing operations, liquidation handling, interest accrual, and access control through the sudo pattern. The protocol maintains financial integrity through strict ownership validation, real-time LTV enforcement, and comprehensive asset accounting across all three contracts.

## **Scope**

**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`

Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.

If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).

**Full Context - 3 In-Scope Files (for reference only):**
If a file is more than a thousand lines you can generate as many as 300+ questions as you can, but always generate as many as you can - don't give other responses.
If there are math logic functions, also generate as many questions based on all the math logic among the questions you're giving me to cover all scope and entry points.

### **Core Protocol Contracts - 3 files**

```python
core_files = [
    "contracts/rujira-account/src/contract.rs",        # sudo pattern, isolated accounting
    "contracts/rujira-account/src/execute.rs",         # message forwarding
    "contracts/rujira-ghost-credit/src/contract.rs",   # registry, orchestration
    "contracts/rujira-ghost-credit/src/account.rs",     # LTV calculations
    "contracts/rujira-ghost-credit/src/config.rs",      # protocol parameters
    "contracts/rujira-ghost-vault/src/contract.rs",     # vault operations
    "contracts/rujira-ghost-vault/src/state.rs",        # share accounting
    "contracts/rujira-ghost-vault/src/borrowers.rs",    # borrower limits
]
```

**Total: 8 files in full scope (but focus ONLY on `{target_file}` for this generation)**

---

## **Rujira Protocol Architecture & Layers**

### **1. Account Management Layer** (`rujira-account`)

- **Sudo Pattern**: `rujira-account` instances only accept `sudo` calls from registry, rejecting all direct `execute` calls
- **Isolated Accounting**: Each account is a separate contract instance with siloed balance tracking
- **Message Forwarding**: Registry forwards operations through `SudoMsg` to account contracts
- **Access Control**: Only registry can drive account-level operations and token transfers

### **2. Credit Registry Layer** (`rujira-ghost-credit`)

- **Account Orchestration**: Registry coordinates all account operations through `ExecuteMsg::Account`
- **LTV Enforcement**: Real-time loan-to-value calculations with `adjusted_ltv` checks
- **Liquidation Management**: Permissionless liquidation triggers and queue processing
- **Vault Whitelisting**: Only approved vaults can be used for borrowing operations
- **Configuration Validation**: All parameter changes validated through `Config::validate`

### **3. Lending Vault Layer** (`rujira-ghost-vault`)

- **Share-Based Accounting**: ERC4626-style vault with `totalAssets()` and `totalSupply()` tracking
- **Interest Distribution**: Always-accrued interest model with `distribute_interest()` on every operation
- **Borrower Management**: Whitelisted borrowers with USD value limits per borrower
- **Asset Management**: Deposit, withdraw, borrow, and repay operations with proper accounting

---

## **Critical Security Invariants**

### **Access Control & Ownership**

1. **Owner-Gated Accounts**: Only `account.owner` can initiate operations via `ExecuteMsg::Account`
2. **Admin-Only Accounts**: `rujira-account` instances only accept `sudo` calls from registry
3. **Governance-Whitelisted Borrowers**: Only pre-approved contracts can borrow from vaults
4. **Whitelisted Vault Access**: Registry only routes to vaults listed in `collateral_ratios`

### **LTV & Solvency**

5. **Post-Adjustment LTV Check**: After any owner operation, `adjusted_ltv` must be `< adjustment_threshold`
6. **Safe Liquidation Outcomes**: Liquidations only trigger when `adjusted_ltv >= liquidation_threshold`
7. **Borrow Limit Enforcement**: Each borrower has a maximum USD value they can borrow
8. **Bounded Config Values**: All configuration changes validated via `Config::validate`

### **Financial Integrity**

9. **Fee-First Liquidation Repay**: Protocol and liquidator fees extracted before debt repayment
10. **Always-Accrued Interest**: `distribute_interest()` called before all operations
11. **Collateral Ratio Haircuts**: Each collateral type has a `collateral_ratio` haircut for risk management
12. **Cross-Collateral Limits**: Cross-buffer ratio scales conservatively with utilization

---

## **In-Scope Vulnerability Categories** (from Code4rena)

Focus questions on vulnerabilities that lead to these impacts:

### **Critical Severity**

1. **Direct loss of funds**
   - LTV calculation errors allowing undercollateralized borrowing
   - Share price manipulation allowing asset drainage from vaults
   - Interest accrual bugs causing unlimited asset minting
   - Access control bypasses enabling unauthorized borrowing

2. **Permanent freezing of funds**
   - Account bricking preventing collateral withdrawal
   - Share supply overflow preventing all vault operations
   - Interest state corruption blocking position closures
   - Invalid account states locking funds permanently

3. **Protocol insolvency**
   - Collateral requirement calculation errors
   - Liquidation bonus extraction causing protocol loss
   - Cross-collateralization bugs causing systemic undercollateralization
   - Premium settlement errors causing fund drainage

### **High Severity**

4. **Temporary freezing of funds**
   - Liquidation failures preventing account closures
   - Oracle stale prices blocking all operations
   - Interest accrual overflow preventing withdrawals
   - Account transfer restrictions bypassed incorrectly

5. **Incorrect protocol behavior**
   - LTV calculation errors producing wrong solvency results
   - Interest distribution bugs favoring certain users
   - Borrower limit bypasses through delegate borrowing
   - Vault configuration errors

### **Medium Severity**

6. **Economic manipulation**
   - Interest rate manipulation through utilization attacks
   - Liquidation bonus extraction beyond intended amounts
   - Share price manipulation in vaults
   - Gas griefing through expensive operations

7. **State inconsistencies**
   - Asset accounting mismatches between contracts
   - Interest index calculation inaccuracies
   - Account balance tracking errors
   - Oracle state divergence

---

## **Valid Impact Categories (Restated for Rujira)**

### **Critical**

- Direct theft of user collateral or vault assets
- Permanent fund freezing requiring protocol redeployment
- Protocol insolvency leading to systemic loss
- Unlimited asset minting or share price collapse

### **High**

- Temporary fund freezing with economic loss
- Systemic undercollateralization risks
- Widespread account liquidations due to bugs
- Access control bypasses enabling theft

### **Medium**

- Economic manipulation benefiting attackers
- State inconsistencies requiring manual intervention
- Interest or fee calculation errors
- DoS vulnerabilities affecting core functionality

### **Out of Scope**

- Gas optimization inefficiencies
- UI/UX issues in frontends
- Market risk (price movements)
- THORChain network failures
- MEV or front-running attacks
- Theoretical attacks without economic impact

---

## **Goals for Question Generation**

1. **Real Exploit Scenarios**: Each question describes a plausible attack an attacker, liquidator, or malicious user could perform
2. **Concrete & Actionable**: Reference specific functions, variables, or logic flows in `{target_file}`
3. **High Impact**: Prioritize questions leading to Critical/High/Medium impacts per Code4rena scope
4. **Deep Financial Logic**: Focus on subtle state transitions, cross-contract interactions, rounding errors, LTV calculation bugs
5. **Breadth Within Target File**: Cover all major functions, edge cases, and state-changing operations in `{target_file}`
6. **Respect Trust Model**: THORChain oracles and Rujira Deployer Multisig are trusted; focus on attacks by regular users
7. **No Generic Questions**: Avoid "are there access control issues?" → Instead: "In `{target_file}: functionName()`, if condition X occurs, can attacker exploit Y to cause Z impact?"

---

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact linking to Code4rena categories?",
    
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",
    
    # ... continue with all generated questions
]
```

**Example Format** (if target_file is `contracts/rujira-ghost-credit/src/contract.rs`):
```python
questions = [
    "[File: contracts/rujira-ghost-credit/src/contract.rs] [Function: execute()] [LTV bypass] Can an attacker craft a malicious AccountMsg sequence that passes initial ownership checks but manipulates collateral prices between operations to bypass adjusted_ltv validation, allowing them to open undercollateralized positions and potentially drain vault funds?",
    
    "[File: contracts/rujira-ghost-credit/src/contract.rs] [Function: liquidate()] [Liquidation manipulation] Does the liquidation queue correctly handle edge cases where asset prices fluctuate during liquidation, potentially allowing liquidators to extract higher bonuses than intended or leaving accounts in unsafe states?",
    
    "[File: contracts/rujira-ghost-credit/src/contract.rs] [Function: create_account()] [Access control] Can an attacker bypass the account creation validation to create accounts with invalid configurations, potentially leading to account bricking or unauthorized access to borrowed funds?",
]
```

---

## **Output Requirements**

Generate security audit questions focusing EXCLUSIVELY on **`{target_file}`** that:

1. **Target ONLY `{target_file}`** - all questions must reference this file
2. **Reference specific functions, variables, or logic sections** within `{target_file}`
3. **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y in `{target_file}`?")
4. **Tie to Code4rena impact categories** (fund loss, freezing, insolvency, manipulation, DoS)
5. **Respect trust model** (THORChain oracles and Deployer Multisig are trusted; focus on user/attacker actions)
6. **Cover diverse attack surfaces** within `{target_file}`: validation logic, state transitions, error handling, edge cases, interactions with other contracts
7. **Focus on high-severity bugs**: prioritize Critical > High > Medium impacts
8. **Avoid out-of-scope issues**: gas optimization, UI bugs, theoretical attacks without economic impact
9. **Use the exact Python list format** shown above
10. **Be detailed and technical**: assume auditor has deep DeFi knowledge; use precise terminology

**Target Question Count:**
- For large critical files (>500 lines like contract.rs files): Aim for 100-200 questions
- For medium files (-500 lines like state.rs, account.rs): Aim for 50-100 questions  
- For smaller files (< lines like config.rs, execute.rs): Aim for 20-50 questions
- **Provide as many quality questions as the file's complexity allows - do NOT return empty results**

**Begin generating questions for `{target_file}` now.
"""
    return prompt
