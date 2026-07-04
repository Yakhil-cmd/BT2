import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "starkware-libs/starknet-staking"
# todo: the name of the repository
REPO_NAME = "starknet-staking"
run_number = os.environ.get('GITHUB_RUN_NUMBER') or os.environ.get('CI_PIPELINE_IID', '0')


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index"""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repositories.json")
    if not os.path.exists(repo_file):
        return []

    try:
        with open(repo_file, 'r', encoding='utf-8') as f:
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
    "L1/starkware/solidity/stake/RewardSupplierStorage.sol",
    "L1/starkware/solidity/stake/RewardSupplierExternalInterfaces.sol",
    "L1/starkware/solidity/stake/RewardSupplier.sol",
    "L1/starkware/solidity/stake/MintManager.sol",
    "L1/starkware/solidity/stake/PeriodMintLimit.sol",
    "L1/starkware/solidity/upgrade/ProxySupportImpl.sol",
    "L1/starkware/solidity/libraries/Addresses.sol",
    "L1/starkware/solidity/libraries/NamedStorage8.sol",
    "L1/starkware/solidity/libraries/AccessControl.sol",
    "L1/starkware/solidity/libraries/RolesLib.sol",
    "L1/starkware/solidity/interfaces/ContractInitializer.sol",
    "L1/starkware/solidity/interfaces/MGovernance.sol",
    "L1/starkware/solidity/interfaces/ProxySupport.sol",
    "L1/starkware/solidity/interfaces/Identity.sol",
    "L1/starkware/solidity/interfaces/BlockDirectCall.sol",
    "L1/starkware/solidity/components/GovernanceStub.sol",
    "L1/starkware/solidity/components/Roles.sol",
    "src/staking/staking.cairo",
    "src/staking/interface.cairo",
    "src/reward_supplier/reward_supplier.cairo",
    "src/reward_supplier/interface.cairo",
    "src/pool/pool.cairo",
    "src/pool/interface.cairo",
    "src/minting_curve/minting_curve.cairo",
    "src/minting_curve/interface.cairo",
]

target_scopes = [
    "Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency",
    "High: Theft of unclaimed yield or unclaimed royalties",
    "High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds",
    "Medium: Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption",
]

def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit + fuzzing questions for one Starknet Staking target.

    ```
    target_file format:
    "'File Name: src/staking/staking.cairo -> Scope: Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency'"
    ```
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact Starknet Staking target:

    {target_file}

    Use live context from the project if available: staking core, delegation pools, reward supplier, minting curve, attestation, token activation, staking power traces, epoch transitions, L1/L2 reward messaging, and accounting helpers.

    Protocol focus:
    This repository implements Starknet staking, delegation pools, attestation-gated rewards, reward supply, and minting logic. Focus on theft, freezing, overpayment, under-accounting, privilege bypass, unsafe L1/L2 message handling, and broken epoch or pool state transitions reachable from production entrypoints.

    Core invariants:

    * Stake, delegation, undelegation, pool switch, and reward-claim flows must preserve value and authorization.
    * Reward updates must not overpay, double count, misroute, or bypass attestation and epoch gating.
    * Pool, staker, and total-stake traces must remain internally consistent across state transitions.
    * Only intended roles, contracts, and validated L1 handlers may mutate privileged config or supply state.
    * Token activation, minting, attestation, and reward-supplier flows must not permanently lock funds or desync accounting.

    Rules:

    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Attacker is unprivileged: staker, delegator, reward address, arbitrary public caller, or L1 message sender when the handler validation is part of the target.
    * Do not rely on governor/token-admin/security-admin compromise, leaked keys, bridge compromise, malicious token contracts, phishing, or third-party dependency compromise.
    * Generate 20 to 30 high-signal questions.
    * At least 70% must be multi-step flow, invariant, fuzz, accounting, state-transition, or cross-module questions.
    * Every question must be testable by PoC, unit test, fuzz test, invariant test, or differential test.
    * Avoid generic checklist questions and repeated root causes.
    * Note any question u must target valid issue u think could be possible

    High-value attack surfaces:

    * Staking entrypoints: stake, increase, unstake intent/action, reward claim, pool deployment, token changes, and migration.
    * Pool flows: enter, add, exit intent/action, switch pool, member reward accounting, and trace updates.
    * Reward flows: reward supply updates, mint requests, claim paths, block-reward math, and cross-contract transfers.
    * Attestation and epochs: epoch windows, target block selection, reward gating, and replay/double-attest style mistakes.
    * L1/L2 boundaries: L1 handler authorization, minting inputs, total supply updates, and bridge-facing assumptions.

    Impact mapping:

    * Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency
    * High: Theft of unclaimed yield or unclaimed royalties
    * High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds
    * Medium: Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption

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
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: fuzz/state-test PARAMETERS and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Starknet Staking exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production Starknet Staking code.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, docs, mocks, scripts, configs, build files, IDE files, package metadata, vendored libraries, and local-only fixtures.

## Objective
Decide whether the question leads to a real, reachable Starknet Staking vulnerability.
The attacker must be unprivileged and enter through a public contract call, staking or pool action, reward claim path, attestation flow, or an L1 handler whose validation is in scope.
The impact must match one of the allowed Starknet Staking impacts below.
Prefer #NoVulnerability unless the path is concrete, local-testable, and bounty-grade.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency
- High: Theft of unclaimed yield or unclaimed royalties
- High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds
- Medium: Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production Starknet Staking files/functions.
3. Check the relevant guard: role gating, caller checks, epoch windows, attestation validation, trace/accounting math, token movement, L1 handler authorization, or cross-contract assumptions.
4. Decide whether the questioned invariant can actually break under intended deployment.
5. Prove root cause with file/function/line references.
6. Confirm realistic likelihood and exact scoped impact.
7. Reject if current validation already prevents the exploit.

## Reject Immediately
- Requires trusted role, leaked key, privileged operator access, bridge compromise, or token-admin/governor compromise.
- Requires third-party dependency compromise, phishing, or unsupported external assumptions.
- Only affects tests, docs, configs, scripts, mocks, local fixtures, vendored libraries, or local deployment choices.
- External dependency behavior is the only cause.
- Impact is only logging, observability, local misconfiguration, non-security correctness, harmless revert, stale read, rejected update, or theoretical risk.
- No concrete scoped impact or no realistic exploit path.

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
    Generate a short cross-project analog scan prompt for Starknet Staking.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production Starknet Staking files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, docs, build files, IDE files, configs, resources, local fixtures, vendored libraries, or package metadata as audited targets.

## Objective
Use the external report's vulnerability class as a hint to find valid issues based on the Starknet Staking bounty scope.
Focus on reachable issues triggered by an unprivileged staker, delegator, reward address, public caller, or L1 message sender where validation is in scope.
Only report an analog if this codebase has its own reachable root cause and the impact matches one of the allowed Starknet Staking impacts below.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency
- High: Theft of unclaimed yield or unclaimed royalties
- High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds
- Medium: Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption

## Method
1. Classify vuln type: accounting bug, authorization bypass, attestation bypass, reward misrouting, unsafe L1/L2 message handling, state-transition bug, or token-freeze bug.
2. Map to Starknet Staking components and exact production files.
3. Prove root cause with exact file/function/module/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Explain the attacker-controlled entry path and why this repository's code is a necessary vulnerable step.
6. Reject if the impact does not match one of the allowed Starknet Staking impacts above.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires trusted role, leaked key, privileged operator access, bridge compromise, or token-admin/governor compromise.
- Requires third-party dependency compromise, phishing, or unsupported external assumptions.
- External dependency behavior is the only cause.
- Test/docs/config/build-only issue.
- Theoretical-only issue with no protocol impact.
- Impact is only local misconfiguration, observability noise, logging noise, harmless revert, stale read, or non-security correctness.
- Impact or likelihood missing.

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
    Generate a strict Starknet Staking bounty-style validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and the Starknet Staking bounty scope for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, trusted-operator, leaked-key, host-compromise, bridge-compromise, best-practice, docs/style, config/build-only, gas-fee-only, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, phishing/social engineering, third-party dapp/oracle compromise, missing external context, or unsupported protocol behavior.
- A valid report must be triggerable by an unprivileged user, delegator, staker, reward address, public caller, or by an L1 handler path whose validation is proven insufficient.
- The final impact must match an in-scope bounty impact, not just a generic code bug.
- Reject any issue whose final impact is not one of the allowed Starknet Staking impacts listed below.
- Prefer #NoVulnerability over speculative reports.

## In-Scope Protocol Areas
The claim must affect production in-scope Starknet Staking code or systems, such as:
- Staking core: stake, unstake, reward claim, reward updates, pool linkage, token activation, peer/public-key changes, and migration.
- Delegation pools: enter, add, exit, switch, member accounting, and pool reward distribution.
- Reward flows: reward supplier, minting curve, mint requests, block-reward math, and cross-contract token transfers.
- Attestation and epoch logic: attestation windows, target block calculation, epoch transitions, and reward gating.
- L1/L2 boundaries: authorized L1 handlers, supply updates, bridge-facing assumptions, and cross-layer reward state.

Reject third-party dapps, unlisted public websites, tests, docs, examples, mocks, generated files, local deployment helpers, vendored libraries, and issues that only affect local developer tooling unless the submitted claim proves a direct in-scope Starknet Staking security impact.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Direct theft of user funds, whether at-rest or in-motion, excluding unclaimed yield; Protocol insolvency
- High: Theft of unclaimed yield or unclaimed royalties
- High: Permanent freezing of unclaimed yield or unclaimed royalties; Temporary freezing of funds
- Medium: Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption

Informational, non-security correctness, observability/logging-only, harmless reject/revert, stale read without consensus/state/accounting/security impact, local misconfiguration, and non-demonstrably-exploitable reports are invalid for this validation output.

If the submitted claim does not concretely prove one of the allowed Starknet Staking impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken protocol/security/accounting/authentication/certification assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete impact that exactly matches one allowed Starknet Staking impact above, with realistic likelihood.
6. Reproducible safe proof path: unit PoC, deterministic integration test, invariant test, fuzz test, or exact local manual steps.
7. No obvious rejection reason from SECURITY.md, known issues, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external user or insufficiently checked L1 handler path trigger this?
- Does the code actually behave as claimed?
- Is the impact caused by Starknet Staking production code, not by an external dependency alone?
- Is the funds-loss/freeze/accounting/authorization impact concrete, not hypothetical?
- Does the claim avoid governance compromise, trusted operator assumptions, leaked keys, bridge compromise, and third-party compromise assumptions?
- Would a bounty triager accept the proof?
- What exact test would prove it?

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
[Concrete allowed Starknet Staking bounty impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant/fork test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
