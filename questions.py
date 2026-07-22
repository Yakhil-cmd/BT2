import json
import os

MAX_REPO = 25
SOURCE_REPO = 'codertjay/2026-07-metric-dev-oyakhil-main'
REPO_NAME = '2026-07-metric-dev-oyakhil-main'
run_number = os.environ.get("GITHUB_RUN_NUMBER") or os.environ.get(
    "CI_PIPELINE_IID", "0"
)


def get_cyclic_index(run_number, max_index=100):
    """Convert run number to a cyclic index between 1 and max_index."""
    return (int(run_number) - 1) % max_index + 1


def load_repository_urls():
    """Load repository URLs from repositories.json."""
    repo_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "repositories.json"
    )
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
    'metric-core/contracts/interfaces/callbacks/IMetricOmmModifyLiquidityCallback.sol',
    'metric-core/contracts/interfaces/callbacks/IMetricOmmSwapCallback.sol',
    'metric-core/contracts/interfaces/extensions/IMetricOmmExtensions.sol',
    'metric-core/contracts/interfaces/IExtsload.sol',
    'metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryOwner.sol',
    'metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactoryPoolAdmin.sol',
    'metric-core/contracts/interfaces/IMetricOmmPoolFactory/IMetricOmmPoolFactory.sol',
    'metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolActions.sol',
    'metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolCollectFees.sol',
    'metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPoolFactoryActions.sol',
    'metric-core/contracts/interfaces/IMetricOmmPool/IMetricOmmPool.sol',
    'metric-core/contracts/interfaces/IPriceProvider/IPriceProvider.sol',
    'metric-core/contracts/libraries/BinDataLibrary.sol',
    'metric-core/contracts/libraries/CallExtension.sol',
    'metric-core/contracts/libraries/LiquidityLib.sol',
    'metric-core/contracts/libraries/PoolActions.sol',
    'metric-core/contracts/libraries/PoolStateLibrary.sol',
    'metric-core/contracts/libraries/SignedMath.sol',
    'metric-core/contracts/libraries/Slot0Library.sol',
    'metric-core/contracts/libraries/SwapMath.sol',
    'metric-core/contracts/libraries/ValidateExtensionsConfig.sol',
    'metric-core/contracts/MetricOmmPoolDeployer.sol',
    'metric-core/contracts/MetricOmmPoolFactory.sol',
    'metric-core/contracts/MetricOmmPool.sol',
    'metric-core/contracts/types/FactoryOperation.sol',
    'metric-core/contracts/types/FactoryStorage.sol',
    'metric-core/contracts/types/PoolExtensionsConfig.sol',
    'metric-core/contracts/types/PoolOperation.sol',
    'metric-core/contracts/types/PoolStorage.sol',
    'metric-core/contracts/types/Slot0.sol',
    'metric-core/contracts/utils/MetricReentrancyGuardTransient.sol',
    'metric-periphery/contracts/base/MetricOmmSwapRouterBase.sol',
    'metric-periphery/contracts/base/PeripheryPayments.sol',
    'metric-periphery/contracts/base/SelfPermit.sol',
    'metric-periphery/contracts/common/MetricOmmPoolStateView.sol',
    'metric-periphery/contracts/extensions/base/BaseMetricExtension.sol',
    'metric-periphery/contracts/extensions/DepositAllowlistExtension.sol',
    'metric-periphery/contracts/extensions/OracleValueStopLossExtension.sol',
    'metric-periphery/contracts/extensions/PriceVelocityGuardExtension.sol',
    'metric-periphery/contracts/extensions/SwapAllowlistExtension.sol',
    'metric-periphery/contracts/interfaces/extensions/IDepositAllowlistExtension.sol',
    'metric-periphery/contracts/interfaces/extensions/IOracleValueStopLossExtension.sol',
    'metric-periphery/contracts/interfaces/extensions/IPriceVelocityGuardExtension.sol',
    'metric-periphery/contracts/interfaces/extensions/ISwapAllowlistExtension.sol',
    'metric-periphery/contracts/interfaces/external/IERC20PermitAllowed.sol',
    'metric-periphery/contracts/interfaces/IMetricOmmPoolLiquidityAdder.sol',
    'metric-periphery/contracts/interfaces/IMetricOmmSimpleRouter.sol',
    'metric-periphery/contracts/interfaces/IMetricOmmSwapQuoter.sol',
    'metric-periphery/contracts/interfaces/IMulticall.sol',
    'metric-periphery/contracts/interfaces/IPeripheryPayments.sol',
    'metric-periphery/contracts/interfaces/ISelfPermit.sol',
    'metric-periphery/contracts/interfaces/IWETH9.sol',
    'metric-periphery/contracts/libraries/MetricOmmSwapInputs.sol',
    'metric-periphery/contracts/libraries/MetricOmmSwapPath.sol',
    'metric-periphery/contracts/libraries/MetricOmmSwapQuoteDecode.sol',
    'metric-periphery/contracts/libraries/MetricOmmSwapResults.sol',
    'metric-periphery/contracts/libraries/TransientCallbackPool.sol',
    'metric-periphery/contracts/MetricOmmPoolLiquidityAdder.sol',
    'metric-periphery/contracts/MetricOmmSimpleRouter.sol',
    'smart-contracts-poc/contracts/AnchoredPriceProvider.sol',
    'smart-contracts-poc/contracts/AnchoredProviderFactory.sol',
    'smart-contracts-poc/contracts/interfaces/IAnchoredProviderFactory.sol',
    'smart-contracts-poc/contracts/interfaces/IAnchorSource.sol',
    'smart-contracts-poc/contracts/interfaces/ICompressedOracleV1.sol',
    'smart-contracts-poc/contracts/oracles/compressed/CompressedOracle.sol',
    'smart-contracts-poc/contracts/oracles/compressed/OracleBase.sol',
    'smart-contracts-poc/contracts/oracles/providers/ChainlinkOracle.sol',
    'smart-contracts-poc/contracts/oracles/providers/docs/en/abuse-protection-integration.md',
    'smart-contracts-poc/contracts/oracles/providers/docs/ru/abuse-protection-integration.md',
    'smart-contracts-poc/contracts/oracles/providers/OracleBase.sol',
    'smart-contracts-poc/contracts/oracles/providers/PythOracle.sol',
    'smart-contracts-poc/contracts/oracles/utils/Codebook256.sol',
    'smart-contracts-poc/contracts/oracles/utils/LazerConsumer.sol',
    'smart-contracts-poc/contracts/oracles/utils/TimeMs.sol',
    'smart-contracts-poc/contracts/oracles/utils/U64x32.sol',
    'smart-contracts-poc/contracts/PriceProviderFactory.sol',
    'smart-contracts-poc/contracts/PriceProvider.sol',
    'smart-contracts-poc/contracts/ProtectedPriceProviderL2.sol',
    'smart-contracts-poc/contracts/ProtectedPriceProvider.sol',
]

target_scopes = [
    'Critical. Unprivileged or semi-trusted pool-admin path bypasses fee caps, provider timelock, or pause boundaries and causes direct loss of funds.',
    'Critical. Pool creation binds wrong tokens, scale multipliers, price provider, bin state, admin, or registry identity, enabling fund loss in standard ERC20 pools.',
    'High. Extension validation/order failure skips a required allowlist, stop-loss, price-velocity, or accounting hook during real swaps or liquidity operations.',
    'High. Factory/deployer mismatch lets an attacker spoof, duplicate, or hijack canonical pool identity used by routers, quoters, providers, or state views.',
    'Medium. Pool-admin action honestly within expected setup exceeds configured bounds or bypasses delay and causes loss above Sherlock thresholds.',
    'Medium. Fee destination, protocol fee, bin fee, or collect-fee accounting is misconfigured or misapplied in a way that leaks protocol/user funds.',
]

METRIC_ALLOWED_IMPACT_SCOPE = '## Metric OMM Allowed Impact Gate\nOnly accept contest-relevant impacts:\n- Critical/High/Medium direct loss of user principal, protocol fees, or owed LP assets above Sherlock thresholds.\n- Broken core pool functionality causing loss of funds or unusable withdraw/swap/liquidity flows.\n- Pool insolvency: balances fail to cover LP claims, owed fees, or swap settlement.\n- Swap conservation failure: trader receives more than the oracle/bin curve permits or pool fails to receive owed input.\n- Bad-price execution: stale, inverted, unbounded, or unclamped bid/ask quote reaches a pool swap.\n- Admin-boundary break: pool admin exceeds caps, bypasses timelocks, or factory/oracle role checks are bypassed by an unprivileged path.\nOut of scope: non-standard ERC20 behavior except USDC/USDT, malicious initial pool setup, trusted factory owner/oracle admin actions, correct off-chain oracle data, tests, mocks, scripts, deployments, docs-only issues with no code-level impact, gas-only DoS, crashes, style, or low-value dust.'

SMART_AUDIT_PIVOTS = '## Smart Audit Pivots\n- Factory path: `createPool` and deployer wiring must bind token0 < token1, price provider token pair, scaling multipliers, initial bins, fee caps, admin, fee destination, immutable/mutable provider mode, and pool registry identity.\n- Admin path: pool admin is semi-trusted only inside caps and timelocks; look for bypasses in `setPoolFees`, `setBinAdditionalFees`, pause transitions, provider proposals, and fee collection destinations.\n- Extension config path: `ValidateExtensionsConfig` and `CallExtension` must validate extension addresses, selectors, init data, call order, and failure semantics without letting a pool silently skip or reorder guards.\n- Deployment path: CREATE2/deployer parameters and factory storage must prevent duplicate, misbound, or unregistered pools from being treated as canonical.'


def question_generator(target_file: str) -> str:
    """
    Generate factory, deployment, admin-boundary, and extension-config questions for one Metric OMM target.
    """

    prompt = f"""
    Generate factory/admin/config safety security questions for this exact Metric OMM contest target:

    {target_file}

    Project lens:
    Focus on pool creation, deterministic deployment, token ordering, fee caps, admin fee destinations, price-provider changes, protocol/pool pause levels, extension validation, and bounded pool-admin powers.

    Contest impact gate:
    {METRIC_ALLOWED_IMPACT_SCOPE}

    {SMART_AUDIT_PIVOTS}

    Rules:
    * Treat `File Name:` as the exact file and `Scope:` as the only impact.
    * Assume repo context is accessible; do not ask for code.
    * Attacker is unprivileged: trader, LP, router caller, public pool creator, contract caller, or public oracle pusher where the contract allows it.
    * Standard ERC20 tokens are in scope, including USDC and USDT. Do not rely on non-standard token behavior.
    * Factory owner and oracle admin are trusted. Pool admin is semi-trusted only inside configured caps and timelocks; bypassing those boundaries can be valid.
    * Pools are assumed honestly configured and non-malicious at creation unless the question proves a validation bypass in scoped code.
    * Correct off-chain oracle prices are assumed; only on-chain validation, attribution, staleness, encoding, or clipping failures are in scope.
    * Exclude tests, mocks, scripts, deployments, local tooling, docs-only issues with no code-level impact, gas-only DoS, crashes, style, and dependency-only behavior.
    * Generate 20 to 30 high-signal questions. Avoid generic checklist items and repeated root causes.
    * Name the exact value at risk: token balance, LP shares, owed fees, bin state, bid/ask, price limit, provider address, feed id, timestamp, extension decision, admin cap, or pool registry entry.
    * Every question must be testable with a Foundry unit, integration, fork, or property test.

    Each question must include target symbol, attacker-controlled input, required state, call path, invariant, corrupted value, scoped impact, and proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Symbol: symbol_or_module] Can attacker-controlled CREATE_OR_ADMIN_INPUT under FACTORY_STATE reach CALL_PATH and violate CONFIG_OR_AUTHORITY_INVARIANT, corrupting EXACT_POOL_FEE_PROVIDER_OR_EXTENSION_VALUE with scoped impact SCOPE_IMPACT? Proof idea: build a Foundry deployment/admin test over PARAMS_ROLES_TIMERS and assert EXPECTED_FACTORY_BOUNDARY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Metric OMM exploit-question validation prompt.
    """
    return f"""# FACTORY CONFIG AND ADMIN QUESTION REVIEW

## Exploit Question
{question}

## Scope Rules
- Audit only contest-relevant Metric OMM production code for Sherlock contest 1279.
- Ignore tests, mocks, scripts, deployments, generated artifacts, local tooling, and docs-only issues with no code-level impact.
- Do not ask for repo contents or claim files are missing.

## Objective
Decide whether the question leads to a real Metric OMM vulnerability. The attacker must enter through public pool, router, liquidity, permit, oracle-push, provider-read, or pool-creation/admin-boundary flows available in scoped code.

Reject claims needing trusted factory owner, oracle admin, deployment control, malicious pool setup, incorrect off-chain oracle data, or non-standard token behavior. Prefer #NoVulnerability unless the path proves direct fund loss, pool insolvency, bad-price execution, or broken core functionality under the contest rules.

## Required Impacts
{METRIC_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

## Method
1. Trace the public or semi-trusted entrypoint.
2. Map it to exact scoped files and functions.
3. Check role boundary -> parameter validation -> persisted factory/pool state -> delayed or capped action -> downstream swap/liquidity effect.
4. Identify the exact corrupted value and who loses funds or functionality.
5. Reject if existing guards preserve the invariant or impact is below contest thresholds.

## Reject Immediately
- Trusted owner/oracle admin/deployer assumptions without an unprivileged bypass.
- Malicious pool initialization or user-chosen unsafe pool parameters without a scoped validation failure.
- Non-standard ERC20 behavior, except USDC/USDT-compatible edge cases.
- Correctly rejected stale/bad oracle data, harmless bad quotes, or view-only differences with no fund impact.
- Gas-only DoS, crashes, unbounded growth, logs, style, dependency-only behavior, tests, mocks, scripts, deployments, local tooling, or docs-only issues with no code-level impact.

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
    Generate a cross-project analog scan prompt for Metric OMM issues.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Task
Use the external report only as a bug-class seed. Search Metric OMM factory, deployer, admin, fee, provider-change, pause, and extension-config code for a native analog with fund loss or core-functionality impact.

## Required Impacts
{METRIC_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

Report only if this repository has its own reachable root cause, unprivileged or valid semi-trusted trigger, broken invariant, exact corrupted value, and matching target scope or allowed impact. Reject privileged operations, malicious setup assumptions, non-standard tokens, resource-only issues, dependency-only behavior, and anything outside the contest-relevant production surface.

## Work Plan
1. Classify the external bug into one Metric OMM invariant.
2. Map it to exact scoped files/functions.
3. Trace attacker input through production validation and state updates.
4. Identify the wrong token balance, LP claim, fee amount, bid/ask, provider/feed binding, extension decision, callback payment, admin cap, or registry value.
5. Reject if existing guards preserve the invariant or the loss is not contest-relevant.

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
    Generate a strict Metric OMM validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim against contest-relevant Metric OMM production code in this repository.
- Do not invent a stronger claim, change target scope, or upgrade severity without evidence.
- A valid issue must be triggered by an unprivileged trader, LP, router caller, public pool creator, contract caller, or public oracle pusher where allowed by scoped code.
- Factory owner and oracle admin are trusted. Pool admin is semi-trusted only inside caps and timelocks; prove bypass or fund-impacting cap failure.
- Reject malicious setup, incorrect off-chain oracle data, non-standard ERC20 behavior except USDC/USDT, gas-only DoS, crashes, unbounded growth, logs, style, dependency-only bugs, tests, mocks, scripts, deployments, local tooling, and docs-only issues with no code-level impact.
- The final impact must match one `target_scopes` item or allowed impact below, identify the exact corrupted value, and meet Sherlock contest thresholds.

## Required Impacts
{METRIC_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

## Required Checks
1. Exact file/function references in scoped code.
2. Clear broken Metric OMM invariant tied to funds, core functionality, bad-price execution, admin boundary, or provider/oracle integrity.
3. Reachable exploit path: preconditions -> attacker input -> production call path -> bad value.
4. Existing guards reviewed and shown insufficient.
5. Exact wrong value named: token balance, LP shares, owed fees, bin totals, bid/ask, price limit, provider/feed id, timestamp, extension decision, callback context, fee cap, or registry entry.
6. Reproducible proof path: Foundry unit, integration, fork, or property test.

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
[Concrete allowed repository impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
