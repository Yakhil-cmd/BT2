import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 10
# todo: the path from https:///github.com/dfinity/ICRC-1
SOURCE_REPO = "sei-protocol/sei-chain"
# todo: the name of the repository
REPO_NAME = "sei-chain"
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


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for Rootstock/PowPeg security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}


## Rules
- Validate only the submitted claim.
- Check against the RootstockLabs Immunefi impacts in questions.py target_scopes.
- Check that referenced code is in production Java source listed in questions.py scope_files.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher scoped impact.
- Reject leaked-key, privileged-operator, admin-only, configuration-only, phishing/social-engineering, DDoS/brute-force, docs/style, best-practice, and purely theoretical issues.
- Reject if the exploit requires unrealistic assumptions, victim mistakes, public mainnet/testnet testing, missing external context, or unsupported Rootstock/PowPeg behavior.
- A valid remote report must be triggerable indirectly through consensus-valid blockchain, Bridge, Bitcoin, RPC, bitcoind, or HSM-protocol data reachable by powpeg-node.
- Local or physical assumptions are acceptable only for scopes that explicitly say local or physical.
- The final impact must match an in-scope RootstockLabs bounty impact, not just a generic code bug.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, class, method, and line/code references.
2. Clear root cause and broken Rootstock/PowPeg/HSM/Bitcoin security assumption.
3. Reachable exploit path: preconditions -> attacker action/input -> trigger -> bad result.
4. Existing checks/guards reviewed and shown insufficient: release requirements, network/chain-id binding, federation/key-id binding, sighash/value/recipient/UTXO binding, confirmations/reorg handling, HSM response validation, parser bounds, cache replay protection, fee/gas limits, exception handling, and fail-closed behavior.
5. Concrete in-scope impact with realistic likelihood.
6. Reproducible proof path: Java unit/integration test, mocked RSK/Bitcoin/HSM clients, local regtest/fork test, property/fuzz test, invariant test, or exact manual local steps.
7. No obvious rejection reason from known out-of-scope rules, privileges, brute force, or unsupported deployment assumptions.

## Silent Triage Questions
Before output, internally answer:
- Does the attacker model match the exact scope: remote, local, or physical?
- Can the input realistically reach powpeg-node under default/intended production deployment?
- Is the powpeg-node target file a necessary cause of the impact?
- Is the impact caused by this protocol code, not by an external dependency alone?
- Is bridge fund loss/theft, HSM compromise, node crash, network disruption, fee manipulation, or resource impact concrete rather than hypothetical?
- Would an Immunefi triager accept the evidence?
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
[Concrete in-scope impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz/invariant test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt

def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for Sei sei-chain.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production files in questions.py scope_files as accessible context.
- Do not claim missing/inaccessible files.
- Do not ask for repository contents.
- Do not scan tests, docs, build files, IDE files, sample configs, generated files, resources, scripts, mocks, package metadata, or generated code as audited targets.

## Bounty Scope
Only valid if it matches one impact:
- Critical: direct loss >= $5k; unauthorized transfer/mint/burn >= $5k; permanent fund freeze >= $5k with no on-chain fix, excluding general network unavailability, hard fork required.
- High: crash/halt >=1/3 validators without direct validator-node access; permanent chain split requiring hard fork; default RPC crash via malicious block/tx payload propagated through network.
- Medium: malicious proposer freezes blocks >=10 min beyond skipped slots; L0/L1/L2 network bug causes deterministic unintended smart contract execution with no funds at risk; default RPC/gRPC crash via unauthenticated endpoint access; crash/halt >=10% and <1/3 validators via crafted non-bruteforce messages while liveness remains; block production delay >2.5s on realistic validator hardware via crafted tx/messages excluding malicious proposers; permanent fund freeze < $5k with no on-chain fix and hard fork required; direct loss < $5k including unauthorized transfer/mint/burn.
- Low: transaction fee calculation outside protocol bounds; mempool inclusion/ordering outside protocol selection/priority rules; crash/halt <10% validators via crafted non-bruteforce messages while liveness remains.

## Objective
Find whether the same vulnerability class can occur in Sei sei-chain in-scope code.
Use the external report as a hint, not as proof.
Focus on unprivileged users only.
Always match the result to one Bounty Scope impact before deciding validity.

## Method
1. Classify vuln type: parser/deserialization, auth/origin confusion, antehandler/signature validation, EVM/Cosmos address confusion, precompile/module permission bypass, parallel execution race, state divergence, mempool/nonce/recheck bug, consensus/liveness bug, block validation, staking/slashing accounting, bank/token supply accounting, oracle validation, IBC/bridge validation, wasm execution/gas bug, EVM gas/fee/refund bug, replay/cache, upgrade/version confusion, RPC/P2P crash, resource bounds, local storage/state corruption.
2. Map to Sei components and exact production files.
3. Prove root cause with exact file/function/line references.
4. Confirm concrete scoped impact and realistic likelihood.
5. Reject if sei-chain is not a necessary vulnerable step.

## Disqualify Immediately
- No reachable attacker-controlled entry path.
- Requires validator key compromise, governance majority, admin/maintainer/trusted operator action, leaked keys, or private infrastructure access.
- Requires malicious/compromised StateSync Peer or P2P-mode state sync.
- External dependency/app/contract behavior is the only cause.
- Test/docs/config/build/script-only issue.
- Theoretical-only issue with no protocol impact.
- Normal market/oracle/liquidity movement is the only cause.
- Impact is not one of the listed Bounty Scope impacts.
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

