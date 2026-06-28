import json
import os

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "aurora-is-near/aurora-engine"
# todo: the name of the repository
REPO_NAME = "aurora-engine"
run_number = os.environ.get("GITHUB_RUN_NUMBER") or os.environ.get("CI_PIPELINE_IID", "0")


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index."""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    return [url for url in data if isinstance(url, str) and url.strip()]


if run_number == "0":
    BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"
else:
    repository_urls = load_repository_urls()
    if repository_urls:
        run_index = get_cyclic_index(run_number, len(repository_urls))
        BASE_URL = repository_urls[run_index - 1]
    else:
        BASE_URL = f"https://deepwiki.com/{SOURCE_REPO}"

scope_files = [
    "engine/src/accounting.rs",
    "engine/src/contract_methods/admin.rs",
    "engine/src/contract_methods/connector.rs",
    "engine/src/contract_methods/evm_transactions.rs",
    "engine/src/contract_methods/mod.rs",
    "engine/src/contract_methods/silo/mod.rs",
    "engine/src/contract_methods/silo/whitelist.rs",
    "engine/src/contract_methods/xcc.rs",
    "engine/src/engine.rs",
    "engine/src/errors.rs",
    "engine/src/hashchain.rs",
    "engine/src/lib.rs",
    "engine/src/map.rs",
    "engine/src/pausables.rs",
    "engine/src/prelude.rs",
    "engine/src/state.rs",
    "engine/src/xcc.rs",
    "engine-precompiles/src/account_ids.rs",
    "engine-precompiles/src/alt_bn256.rs",
    "engine-precompiles/src/blake2.rs",
    "engine-precompiles/src/bls12_381/g1_add.rs",
    "engine-precompiles/src/bls12_381/g1_msm.rs",
    "engine-precompiles/src/bls12_381/g2_add.rs",
    "engine-precompiles/src/bls12_381/g2_msm.rs",
    "engine-precompiles/src/bls12_381/map_fp2_to_g2.rs",
    "engine-precompiles/src/bls12_381/map_fp_to_g1.rs",
    "engine-precompiles/src/bls12_381/mod.rs",
    "engine-precompiles/src/bls12_381/pairing_check.rs",
    "engine-precompiles/src/hash.rs",
    "engine-precompiles/src/identity.rs",
    "engine-precompiles/src/lib.rs",
    "engine-precompiles/src/modexp.rs",
    "engine-precompiles/src/native.rs",
    "engine-precompiles/src/prelude.rs",
    "engine-precompiles/src/prepaid_gas.rs",
    "engine-precompiles/src/promise_result.rs",
    "engine-precompiles/src/random.rs",
    "engine-precompiles/src/secp256k1.rs",
    "engine-precompiles/src/secp256r1.rs",
    "engine-precompiles/src/utils.rs",
    "engine-precompiles/src/xcc.rs",
    "engine-sdk/src/base64.rs",
    "engine-sdk/src/bls12_381/contract.rs",
    "engine-sdk/src/bls12_381/contract/exports.rs",
    "engine-sdk/src/bls12_381/mod.rs",
    "engine-sdk/src/bls12_381/standalone.rs",
    "engine-sdk/src/bls12_381/standalone/g1.rs",
    "engine-sdk/src/bls12_381/standalone/g2.rs",
    "engine-sdk/src/bls12_381/standalone/utils.rs",
    "engine-sdk/src/bn128.rs",
    "engine-sdk/src/caching.rs",
    "engine-sdk/src/env.rs",
    "engine-sdk/src/error.rs",
    "engine-sdk/src/exports.rs",
    "engine-sdk/src/io.rs",
    "engine-sdk/src/lib.rs",
    "engine-sdk/src/near_runtime.rs",
    "engine-sdk/src/prelude.rs",
    "engine-sdk/src/promise.rs",
    "engine-sdk/src/types.rs",
    "engine-transactions/src/backwards_compatibility.rs",
    "engine-transactions/src/eip_1559.rs",
    "engine-transactions/src/eip_2930.rs",
    "engine-transactions/src/eip_4844.rs",
    "engine-transactions/src/eip_7702.rs",
    "engine-transactions/src/legacy.rs",
    "engine-transactions/src/lib.rs",
    "engine-types/src/account_id.rs",
    "engine-types/src/lib.rs",
    "engine-types/src/parameters/connector.rs",
    "engine-types/src/parameters/engine.rs",
    "engine-types/src/parameters/mod.rs",
    "engine-types/src/parameters/promise.rs",
    "engine-types/src/parameters/silo.rs",
    "engine-types/src/parameters/xcc.rs",
    "engine-types/src/public_key.rs",
    "engine-types/src/storage.rs",
    "engine-types/src/types/address.rs",
    "engine-types/src/types/balance.rs",
    "engine-types/src/types/fee.rs",
    "engine-types/src/types/gas.rs",
    "engine-types/src/types/mod.rs",
    "engine-types/src/types/wei.rs",
    "etc/eth-contracts/contracts/AdminControlled.sol",
    "etc/eth-contracts/contracts/EvmErc20.sol",
    "etc/eth-contracts/contracts/EvmErc20V2.sol",
    "etc/eth-contracts/contracts/IExit.sol",
]
target_scopes = [
    "Critical. Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield",
    "Critical. Permanent freezing of funds",
    "Critical. Insolvency",
    "High. Theft of unclaimed yield",
    "High. Temporary freezing of funds",
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one Aurora Engine target.

    target_file format:
    "'File Name: engine/src/engine.rs -> Scope: Critical. Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact Aurora Engine target:

    {target_file}

    Use live context from the project if available: Aurora Engine transaction execution, EVM account/state/accounting, NEAR host bindings, XCC/promise flows, silo/whitelist restrictions, connector/admin methods, precompiles, SDK/runtime helpers, engine-types parameters, EIP-1559/EIP-2930/EIP-4844/EIP-7702 parsing, and the production Solidity contracts under `etc/eth-contracts/contracts`.

    Protocol focus:
    Aurora Engine is an EVM layer on NEAR that interconnects Ethereum and NEAR ecosystems. Users and contracts submit EVM transactions, move balances through engine accounting, invoke precompiles, bridge through Aurora-specific flows, and rely on the engine to preserve EVM semantics, authorization, accounting, gas charging, promise/XCC safety, and asset backing.

    Core invariants:

    * User funds, protocol-controlled balances, bridged assets, mirrored ERC-20 balances, refunds, and exit-related balances must never be stolen, burned incorrectly, made insolvent, or permanently frozen.
    * EVM execution, nonce handling, gas charging, gas refunds, fee accounting, and state commits must remain consistent across transaction types and cannot let attackers mint value, bypass payment, or desynchronize balances/state.
    * Cross-contract call, promise, callback, silo, whitelist, and connector flows must not let an attacker escalate privileges, bypass isolation, replay value-moving actions, or lock assets indefinitely.
    * Precompiles must not create unauthorized state changes, forged identities, bad accounting, or engine-level inconsistencies that lead to theft, insolvency, or fund freezes.
    * Only authorized admin/configuration paths may pause, whitelist, bridge, register connectors, move protected balances, or change engine behavior affecting user funds.

    Rules:

    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Audit only production code in the current repository that maps to HackenProof in-scope Aurora assets: `engine`, `engine-precompiles`, `engine-sdk`, `engine-transactions`, `engine-types`, and production contracts under `etc/eth-contracts/contracts`.
    * Ignore tests, benches, mocks, examples, docs, generated files, scripts, local tooling, CI files, package metadata, standalone helpers, and local sandbox harnesses as audited targets.
    * Respect current program rules: no public-mainnet or public-testnet testing, no reliance on third-party pricing-oracle behavior alone, no testing assumptions that require third-party smart contracts as the vulnerable component, and no denial-of-service-only reports.
    * The attacker may be an unprivileged EVM user, contract deployer, token holder, calldata sender, relayer through supported transaction paths, or contract interacting with Aurora through intended production interfaces.
    * Do not rely on admin compromise, leaked keys, malicious maintainers, governance capture, compromised NEAR/Ethereum base layers, threshold-validator corruption, third-party oracle errors by themselves, third-party protocol compromise, social engineering, phishing, unsupported deployment changes, or raw traffic flooding.
    * Exclude dependency-only issues, best-practice critiques, static-analysis-only findings, code style issues, centralization-risk complaints, sybil assumptions, lack-of-liquidity claims, and theoretical-only attacks with no concrete exploit path.
    * Generate 10 to 20 high-signal questions.
    * At least 70% must be multi-step flow, invariant, authorization, accounting, fee/gas, state-transition, promise/XCC, transaction-parser, bridge/connector, or cross-module questions.
    * Every question must be testable by a local unit test, fuzz test, invariant test, model test, differential test, Rust integration test, or private sandbox transaction sequence on unmodified code.
    * Avoid generic checklist questions and repeated root causes; prefer concrete boundary mutations such as partial state commits, mismatched gas charging/refunds, replayable exits, nonce/account desync, pause/whitelist bypass, promise result confusion, malformed transaction envelopes, precompile input edge cases, and rounding/accounting drift.
    * Each question must target a plausible issue class for the exact file and scope.

    High-value attack surfaces:

    * Transaction acceptance and execution: envelope parsing, intrinsic gas, fee charging, refunds, nonce progression, chain-id checks, signer recovery, and commit/revert boundaries.
    * Engine accounting and state: balance deltas, storage writes, self-destruct/finalization edge cases, paused-state enforcement, and state snapshot consistency.
    * XCC and promise flows: callback routing, promise result interpretation, cross-contract value movement, reentrancy-like sequencing across promises, and silo whitelist enforcement.
    * Precompiles: account ID mapping, prepaid gas, promise results, randomness, cryptographic precompiles, native/XCC helpers, and host-environment interactions.
    * Connector and bridge-style flows: exit paths, ERC-20 mirror contracts, admin-controlled token actions, bridge accounting, and replay/idempotence protection.
    * Authorization: admin methods, whitelist updates, connector registration, pause controls, and any state-changing path that should stay privileged.

    Impact mapping for this campaign:

    * Valid impacts for these prompts are limited to the five target scopes configured in this repo: direct theft of user funds, permanent freezing of funds, insolvency, theft of unclaimed yield, and temporary freezing of funds.

    Each question must include:

    1. target function/module;
    2. attacker action;
    3. preconditions;
    4. call sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_module] Can an attacker ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: test/fuzz/model PRIVATE_SEQUENCE and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Aurora Engine exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production Aurora Engine code listed in `scope_files`.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, benches, docs, mocks, examples, generated files, scripts, CI files, package metadata, local deployment helpers, standalone utilities, and local tooling.
- Do not perform public-mainnet or public-testnet testing; prefer local tests, private sandbox flows, or deterministic model-based proofs.

## Objective
Decide whether the question leads to a real, reachable Aurora Engine vulnerability.
The attacker must enter through a supported production path such as an EVM transaction, contract deployment, public contract call, precompile invocation, promise/XCC path, connector/admin exposure mistake, ERC-20 mirror flow, or other public engine interface.
The impact must match the provided target scope.
Prefer #NoVulnerability unless the path is concrete, locally testable on unmodified code, and proves one of the impacts in `target_scopes`.

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production files/functions/modules.
3. Check relevant guards: authorization, pause gates, whitelist checks, transaction validation, signature recovery, nonce handling, fee charging, gas refund logic, balance accounting, promise result handling, state commit ordering, and replay/idempotence protection.
4. Decide whether the questioned invariant can actually break under intended Aurora deployment assumptions.
5. Prove root cause with file/function/line references.
6. Confirm realistic likelihood and exact scoped impact.
7. Reject if current validation, accounting, or privilege checks already prevent the exploit.

## Reject Immediately
- Requires admin/operator compromise, leaked private keys, malicious maintainer behavior, governance capture, compromised NEAR/Ethereum infrastructure, validator-threshold failure, third-party oracle errors alone, third-party protocol compromise, unsupported local configuration, social engineering, or public-mainnet/public-testnet testing.
- Only affects tests, docs, configs, scripts, mocks, generated code, local tooling, or standalone helper code outside the in-scope assets.
- External dependency behavior is the only cause.
- Impact is only ordinary gas optimization, performance degradation, observability/logging noise, centralization criticism, liquidity criticism, harmless rejection, non-security correctness, or theory without a concrete exploit path.
- No concrete scoped impact or no realistic exploit path.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield.
- Critical. Permanent freezing of funds.
- Critical. Insolvency.
- High. Theft of unclaimed yield.
- High. Temporary freezing of funds.

## Output
If valid:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If invalid, output exactly:
#NoVulnerability found for this question.
"""


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for Aurora Engine.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production Aurora Engine files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, benches, docs, build files, IDE files, configs, generated files, package metadata, repo automation scripts, local tooling, or deployment-only choices as audited targets.

## Objective
Use the external report's vulnerability class as a hint to find valid issues based on Aurora Engine security impact.
Focus on externally reachable issues triggered by an unprivileged EVM user, contract deployer, token holder, calldata sender, or contract interacting with intended Aurora production interfaces.
Only report an analog if this repository has its own reachable root cause and the impact matches the provided target scope.

## Method
1. Classify the vuln type: fund theft, permanent fund freeze, insolvency, replay, auth bypass, pause/whitelist bypass, transaction-validation bug, gas/fee-accounting bug, promise/XCC state bug, precompile bug, connector/bridge accounting bug, or ERC-20 mirror accounting bug.
2. Map it to Aurora Engine components and exact production files.
3. Prove root cause with exact file/function/module/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Explain the attacker-controlled entry path and why this code is a necessary vulnerable step.
6. Reject if the impact does not match the provided target scope.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires admin/operator compromise, leaked private keys, malicious maintainer behavior, governance capture, compromised base-layer consensus, third-party oracle error alone, third-party protocol compromise, unsupported local configuration, social engineering, or public-mainnet/public-testnet testing.
- External dependency behavior is the only cause.
- Test/docs/config/build/generated/local-tooling/deployment-only issue.
- Theoretical-only issue with no protocol impact.
- Impact is only ordinary gas optimization, network outage, performance degradation, griefing without one of the configured scoped impacts, local misconfiguration, observability noise, harmless rejection, or non-security correctness.
- Impact or likelihood missing.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield.
- Critical. Permanent freezing of funds.
- Critical. Insolvency.
- High. Theft of unclaimed yield.
- High. Temporary freezing of funds.

## Output (Strict)
If valid analog exists, output:

### Title
[Clear vulnerability statement] - ([File: file_path])

### Summary
### Finding Description
### Impact Explanation
### Likelihood Explanation
### Recommendation
### Proof of Concept

If not, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict Aurora Engine validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check current HackenProof Aurora Smart Contract rules for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, operator-only, trusted-maintainer, leaked-key, best-practice, docs/style, gas-optimization-only, performance-only, dependency-only, third-party-oracle-data-only, front-running-only, raw-DoS-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, unsupported deployment changes, compromised NEAR/Ethereum infrastructure, governance capture, validator-threshold corruption, third-party protocol compromise, social engineering, or public-mainnet/public-testnet testing.
- A valid report must be triggerable by an unprivileged external actor through a supported Aurora path: public engine method, EVM transaction, contract deployment, precompile call, promise/XCC flow, connector/bridge-facing flow, or public Solidity contract call in the in-scope contracts.
- The final impact must match one of the `target_scopes`, not just a generic code bug.
- Prefer #NoVulnerability over speculative reports.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield.
- Critical. Permanent freezing of funds.
- Critical. Insolvency.
- High. Theft of unclaimed yield.
- High. Temporary freezing of funds.

If the submitted claim does not concretely prove one of the allowed impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken protocol/security/accounting assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete impact that exactly matches one allowed Aurora Engine impact above, with realistic likelihood.
6. Reproducible proof path: Rust unit/integration/fuzz/model/differential test, private sandbox transaction sequence, or justified local proof when direct execution is not enough.
7. No obvious rejection reason from the current HackenProof rules, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external user or contract trigger this through an intended Aurora interface?
- Does the code actually behave as claimed?
- Is the impact caused by this repository, not by an external dependency alone?
- Is the theft/freeze/insolvency impact concrete, not hypothetical?
- Would a responsible-disclosure triager accept the proof under the current Aurora rules?
- What exact local test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the bug and impact]

## Finding Description
[Exact code path, root cause, exploit flow, and why existing checks fail]

## Impact Explanation
[Concrete allowed Aurora Engine impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or local test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
