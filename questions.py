import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = "polkadot-fellows/runtimes"
# todo: the name of the repository
REPO_NAME = "runtimes"

run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')


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
    # =================================================================================
    # Custom pallets and shared runtime logic
    # =================================================================================
    "pallets/remote-proxy/src/lib.rs",
    "pallets/rc-migrator/src/lib.rs",
    "pallets/ah-ops/src/lib.rs",
    "relay/common/src/lib.rs",

    # =================================================================================
    # Relay Chain runtimes
    # =================================================================================
    "relay/polkadot/src/lib.rs",
    "relay/polkadot/src/xcm_config.rs",
    "relay/polkadot/src/impls.rs",
    "relay/polkadot/src/governance/mod.rs",
    "relay/polkadot/src/governance/origins.rs",
    "relay/polkadot/src/governance/tracks.rs",
    "relay/kusama/src/lib.rs",
    "relay/kusama/src/xcm_config.rs",
    "relay/kusama/src/governance/mod.rs",
    "relay/kusama/src/governance/origins.rs",
    "relay/kusama/src/governance/tracks.rs",
    "relay/kusama/src/governance/fellowship.rs",

    # =================================================================================
    # Asset Hub runtimes
    # =================================================================================
    "system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/xcm_config.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/bridge_to_ethereum_config.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/treasury.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/staking/mod.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/staking/nom_pools.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/staking/stepped_curve.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/governance/mod.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/governance/origins.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/src/governance/tracks.rs",
    "system-parachains/asset-hubs/asset-hub-polkadot/primitives/src/lib.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/xcm_config.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/treasury.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/staking/mod.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/staking/nom_pools.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/governance/mod.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/governance/origins.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/src/governance/tracks.rs",
    "system-parachains/asset-hubs/asset-hub-kusama/primitives/src/lib.rs",

    # =================================================================================
    # Bridge Hub runtimes
    # =================================================================================
    "system-parachains/bridge-hubs/bridge-hub-polkadot/src/lib.rs",
    "system-parachains/bridge-hubs/bridge-hub-polkadot/src/xcm_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_common_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_ethereum_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-polkadot/src/bridge_to_kusama_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-polkadot/primitives/src/lib.rs",
    "system-parachains/bridge-hubs/bridge-hub-kusama/src/lib.rs",
    "system-parachains/bridge-hubs/bridge-hub-kusama/src/xcm_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-kusama/src/bridge_to_polkadot_config.rs",
    "system-parachains/bridge-hubs/bridge-hub-kusama/primitives/src/lib.rs",

    # =================================================================================
    # Other system parachains
    # =================================================================================
    "system-parachains/coretime/coretime-polkadot/src/lib.rs",
    "system-parachains/coretime/coretime-polkadot/src/coretime.rs",
    "system-parachains/coretime/coretime-polkadot/src/xcm_config.rs",
    "system-parachains/coretime/coretime-kusama/src/lib.rs",
    "system-parachains/coretime/coretime-kusama/src/coretime.rs",
    "system-parachains/coretime/coretime-kusama/src/xcm_config.rs",
    "system-parachains/people/people-polkadot/src/lib.rs",
    "system-parachains/people/people-polkadot/src/people.rs",
    "system-parachains/people/people-polkadot/src/assets.rs",
    "system-parachains/people/people-polkadot/src/xcm_config.rs",
    "system-parachains/people/people-kusama/src/lib.rs",
    "system-parachains/people/people-kusama/src/people.rs",
    "system-parachains/people/people-kusama/src/xcm_config.rs",
    "system-parachains/collectives/collectives-polkadot/src/lib.rs",
    "system-parachains/collectives/collectives-polkadot/src/xcm_config.rs",
    "system-parachains/collectives/collectives-polkadot/src/impls.rs",
    "system-parachains/collectives/collectives-polkadot/src/parameters.rs",
    "system-parachains/collectives/collectives-polkadot/src/ambassador/mod.rs",
    "system-parachains/collectives/collectives-polkadot/src/ambassador/origins.rs",
    "system-parachains/collectives/collectives-polkadot/src/ambassador/tracks.rs",
    "system-parachains/collectives/collectives-polkadot/src/fellowship/mod.rs",
    "system-parachains/collectives/collectives-polkadot/src/fellowship/origins.rs",
    "system-parachains/collectives/collectives-polkadot/src/fellowship/tracks.rs",
    "system-parachains/collectives/collectives-polkadot/src/secretary/mod.rs",
    "system-parachains/bulletin/bulletin-polkadot/src/lib.rs",
    "system-parachains/bulletin/bulletin-polkadot/src/apis.rs",
    "system-parachains/bulletin/bulletin-polkadot/src/xcm_config.rs",
    "system-parachains/encointer/src/lib.rs",
    "system-parachains/encointer/src/xcm_config.rs",
    "system-parachains/encointer/src/impls.rs",
    "system-parachains/encointer/src/treasuries_xcm_payout.rs",
    "system-parachains/common/src/lib.rs",
    "system-parachains/common/src/randomness.rs",
]


target_scopes = [
    "Critical. Unauthorized asset mint, burn, withdraw, reserve release, or cross-chain balance mismatch reachable by a normal user in `relay/*/src/lib.rs`, `system-parachains/asset-hubs/*/src/{lib.rs,xcm_config.rs,treasury.rs,staking/*}`, or `system-parachains/people/*/src/assets.rs`, causing direct loss of funds or unbacked assets",
    "Critical. Forged, replayed, stale, or mismapped proof, proxy, or origin data in `pallets/remote-proxy/src/lib.rs`, `relay/*/src/xcm_config.rs`, or `system-parachains/*/src/xcm_config.rs` allowing unprivileged dispatch, unauthorized asset movement, or execution as another account/chain",
    "Critical. XCM router, barrier, origin-conversion, or filter bypass in `relay/*/src/{lib.rs,xcm_config.rs}`, `system-parachains/asset-hubs/*/src/{lib.rs,xcm_config.rs}`, or `system-parachains/bridge-hubs/*/src/{lib.rs,xcm_config.rs}` that lets a normal user reach calls, exports, or asset paths they should not reach",
    "Critical. Bridge message, queue, or settlement flaw in `system-parachains/bridge-hubs/*/src/{lib.rs,xcm_config.rs,bridge_*_config.rs}` or `system-parachains/asset-hubs/asset-hub-polkadot/src/bridge_to_ethereum_config.rs` causing theft, duplicate delivery, replay, unauthorized unlock, or permanent asset loss/freeze",
    "Critical. Runtime logic error in `relay/*/src/lib.rs`, `system-parachains/*/src/lib.rs`, `system-parachains/*/src/*.rs`, or `pallets/ah-ops/src/lib.rs` that lets an unprivileged user violate intended runtime behaviour, create unauthorized state changes, or escalate privileges",
    "Critical. Crowdloan, lease, staking, treasury, payout, or remote-migration accounting bug in `pallets/ah-ops/src/lib.rs`, `relay/common/src/lib.rs`, `system-parachains/asset-hubs/*/src/{staking/*,treasury.rs}`, or `pallets/rc-migrator/src/lib.rs` that lets a normal user steal funds, claim twice, or permanently lock assets",
    "High. Crafted but valid user input causes network-wide halt, stuck queue, or permanent message blockage in `relay/*/src/lib.rs`, `system-parachains/bridge-hubs/*/src/lib.rs`, `system-parachains/bulletin/bulletin-polkadot/src/apis.rs`, or `pallets/remote-proxy/src/lib.rs`",
    "High. Reachable fee, weight, dispatch, or queue-accounting asymmetry in `relay/*/src/lib.rs`, `system-parachains/*/src/lib.rs`, or `*/xcm_config.rs` lets a normal user get unauthorized execution, grief critical paths at low cost, or force persistent state inconsistency",
]


scope_scan = [
]
def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit + fuzzing questions for one Polkadot Fellows runtime target.

    ```
    target_file format:
    "'File Name: relay/polkadot/src/lib.rs -> Scope: Critical. Unauthorized asset mint or state transition break'"
    """

    prompt = f"""
    ```
    
    Generate exploit-focused security audit and fuzzing questions for this exact Polkadot Fellows runtimes target:
    
    {target_file}
    
    Project focus:
    This repo defines Polkadot, Kusama, Asset Hub, Bridge Hub, Coretime, People, Collectives, Bulletin, Encointer, and shared runtime pallets. The main bounty focus is bugs that compromise intended runtime behaviour, especially asset accounting, origin isolation, XCM, bridge settlement, proxy proofs, and runtime dispatch rules.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Rust symbols when possible.
    * Attacker is unprivileged only: a normal signed user, proxy user, or attacker-controlled account using valid extrinsics/XCM through supported runtime paths.
    * Never assume sudo, governance, fellowship, collator, validator, relayer, operator, node, peer, or leaked keys.
    * Do not rely on mocked origins, handcrafted internal helpers, direct storage writes, or impossible external-chain assumptions.
    * Generate 10 to 18 high-signal questions.
    * At least 70% must be multi-step flow, invariant, accounting, origin, replay, XCM, bridge, or cross-module questions.
    * Every question must be testable by unit test, xcm-emulator test, fuzz test, invariant test, or differential test.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * No unprivileged user can mint, unlock, move, or burn assets they do not control.
    * Runtime origins, proxy proofs, and XCM origins must not be forgeable, stale-reusable, or replayable.
    * Cross-chain asset accounting must stay balanced across local, reserve, and bridged representations.
    * Filters, barriers, routers, fee checks, and weight checks must not be bypassed.
    * Runtime behaviour must stay deterministic and must not admit unauthorized privileged calls.
    * Crafted but valid user input must not permanently halt critical queues or freeze user funds.

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
    "[File: {target_file}] [Function: symbol_or_module] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: test/fuzz PARAMETERS and assert EXPECTED_PROPERTY.",
    ]
    """
    return prompt

def audit_format(security_question: str) -> str:
    """
    Generate a focused Polkadot runtimes exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- The referenced runtime file/path exists. Do not say files are missing.
- Do not ask for code. Use available repository context.
- Analyze only this question and only the scoped impact.
- Attacker is unprivileged only: a signed user, proxy user, or attacker-controlled account using real runtime/XCM paths.
- Ignore admin-only, governance-only, node-only, relayer-only, leaked-key, docs, style, gas-only, and best-practice issues.
- Privileged functions matter only if they create a later user-triggered exploit path.
- Do not rely on mocked origins, direct helper calls, direct storage mutation, malicious peers/nodes, or impossible external-chain assumptions.

## Mission
Prove or disprove this as a real runtime bug.

Check:
- exact reachable Rust path;
- attacker-controlled entry path from extrinsic, proxy, XCM, bridge, or runtime-dispatch flow;
- state changes before/after cross-module, queue, or asset-accounting transitions;
- whether origin conversion, filters, barriers, proxy proof checks, fee checks, or weight checks stop it;
- whether the scoped impact is concrete;
- whether a Rust unit/integration test, xcm-emulator test, or fuzz/invariant test can reproduce it.

## Core Invariants
- User-controlled assets must remain fully backed and cannot be stolen, duplicated, or permanently frozen.
- Runtime origins, proxy proofs, and XCM origins must not be forgeable or replayable.
- Bridge and XCM messages must only execute through intended routes with correct accounting.
- Filters, barriers, fee logic, and weight logic must not be bypassable by normal users.
- The runtime must not accept unauthorized privileged state transitions.
- Critical queues and message paths must not be permanently halted by valid user input.

## Valid Only If
1. Exact file/function/line range exists.
2. Root cause is a real missing check, bad accounting, replay, origin confusion, unsafe parsing, or logic error.
3. Exploit path is: preconditions -> attacker action/data -> trigger -> bad state/result.
4. Existing protections are reviewed and insufficient.
5. Impact matches the scoped impact.
6. PoC/test idea has clear assertions.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker inputs, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact]

### Likelihood Explanation
[Preconditions, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Rust integration test, xcm-emulator test, or fuzz/invariant test plan with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for Polkadot runtimes security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- Reject admin-only, governance-only, node-only, relayer-only, leaked-key, best-practice, docs/style, gas-only, mocked-path, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, direct storage mutation, mocked XCM/origins, or unsupported protocol behavior.
- A valid report must be triggerable by an unprivileged user, unless the claim proves privilege escalation from a user path.
- The final impact must match an in-scope bounty impact for runtimes/bridge paths, not just a generic code bug.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken security/accounting assumption.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient.
5. Concrete in-scope impact with realistic likelihood.
6. Reproducible proof path: unit PoC, fork test, invariant/fuzz test, or exact manual steps.
7. No obvious rejection reason from SECURITY.md, known issues, privileges, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can a normal external user trigger this through a real runtime or XCM path?
- Does the code actually behave as claimed?
- Is the impact caused by the runtime code, not by a malicious node, peer, or external dependency alone?
- Is the loss/freeze/insolvency concrete, not hypothetical?
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
[Concrete in-scope impact and severity rationale]

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


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for Polkadot runtimes.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat in-scope runtime files as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.

## Objective
Find whether the same vulnerability class can occur in this repo's in-scope runtime code.
Use the external report as a hint, not as proof.

Note: Check SECURITY.md / Researcher.Md and think in this actual way.
Note: Never generate a report that would result in an out-of-scope and rejected vulnerability.

## Method
1. Classify vuln type (auth, accounting, state transition, parsing/deserialization, crypto, replay, reentrancy, DoS).
2. Map the vulnerability pattern to relay, Asset Hub, Bridge Hub, or shared runtime architecture to find a valid analog.
3. Prove root cause with exact file/function/line references in the codebase.
4. Confirm concrete impact + realistic likelihood for an unprivileged user.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Trusted-role compromise required.
- Only mocked XCM/origin/helper paths are shown.
- Theoretical-only issue with no protocol impact.
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
