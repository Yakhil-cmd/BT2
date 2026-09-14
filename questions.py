import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 25
# todo: the path from https://github.com/byteball/ocore
SOURCE_REPO = "byteball/ocore"
# todo: the name of the repository
REPO_NAME = "ocore"
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
    # =================================================================================
    # Unit/joint validation: the rules that decide whether a posted unit is accepted
    # =================================================================================
    "validation.js",
    "validation_utils.js",
    "joint_storage.js",
    "writer.js",
    "archiving.js",
    "storage.js",
    "constants.js",

    # =================================================================================
    # Authorization: address definitions, authentifiers, hashing and signatures
    # =================================================================================
    "definition.js",
    "signature.js",
    "object_hash.js",
    "object_length.js",
    "string_utils.js",
    "chash.js",
    "merkle.js",
    "signed_message.js",

    # =================================================================================
    # DAG ordering, stability, main chain and graph reachability
    # =================================================================================
    "main_chain.js",
    "graph.js",
    "parent_composer.js",
    "mc_outputs.js",

    # =================================================================================
    # Value accounting: inputs, outputs, balances, commissions, witnessing earnings
    # =================================================================================
    "inputs.js",
    "balances.js",
    "headers_commission.js",
    "paid_witnessing.js",
    "composer.js",

    # =================================================================================
    # Assets: issuance, transfer conditions, divisible and indivisible private payments
    # =================================================================================
    "divisible_asset.js",
    "indivisible_asset.js",
    "private_payment.js",

    # =================================================================================
    # Autonomous Agents: definition validation, trigger execution, response accounting
    # =================================================================================
    "aa_validation.js",
    "aa_composer.js",
    "aa_addresses.js",

    # =================================================================================
    # Oscript/OJSON: parsing, validation and deterministic evaluation of AA formulas
    # =================================================================================
    "formula/index.js",
    "formula/parse_ojson.js",
    "formula/validation.js",
    "formula/evaluation.js",
    "formula/common.js",
    "formula/grammars/ojson.ne",
    "formula/grammars/oscript.ne",

    # =================================================================================
    # Oracles, attestations, order-provider votes and system vars read by AAs
    # =================================================================================
    "data_feeds.js",
    "initial_votes.js",
    "my_witnesses.js",
    "arbiters.js",

    # =================================================================================
    # Wallets, multisig cosigners and peer-to-peer contract flows a counterparty drives
    # =================================================================================
    "wallet.js",
    "wallet_general.js",
    "wallet_defined_by_keys.js",
    "wallet_defined_by_addresses.js",
    "device.js",
    "prosaic_contract.js",
    "arbiter_contract.js",
    "private_profile.js",
    "uri.js",

    # =================================================================================
    # Persistence and concurrency the consensus and AA writes depend on
    # =================================================================================
    "db.js",
    "sqlite_pool.js",
    "mysql_pool.js",
    "kvstore.js",
    "mutex.js",
]


target_scopes = [
    "Critical. An attacker spends outputs of an address whose private keys they do not hold, because authorization is evaluated wrongly: validateAuthentifiers and pathIncludesOneOfAuthentifiers in definition.js, sig/hash/address/and/or/r-of-set/cosigned-by handling, chash derivation in chash.js, getUnitHashToSign and getSourceString in object_hash.js and string_utils.js, or verification in signature.js accepts authentifiers over a payload or definition the owner never authorized.",
    "Critical. The same output is spent twice and both spends end up stable, because double-spend detection fails: checkForDoublespends and input uniqueness in validation.js, serial/nonserial classification, sequence marking in writer.js saveJoint, purgeUncoveredNonserialJoints in joint_storage.js, or the unspend queries in archiving.js let a conflicting pair of units both keep their outputs spendable.",
    "Critical. Bytes or asset units are created out of nothing, because value accounting does not balance: validatePaymentInputsAndOutputs in validation.js, coin selection and confirmation conditions in inputs.js, headers-commission attribution in headers_commission.js calcHeadersCommissions, witnessing earnings in paid_witnessing.js calcWitnessEarnings, oversize/tps fee computation in storage.js, or balance updates in balances.js credit an input twice or let outputs plus fees exceed inputs.",
    "Critical. An attacker's trigger makes an Autonomous Agent pay out funds it was never meant to release, because aa_composer.js mishandles the response: handleTrigger payment and output construction, sortOutputs, bounce and bounce-fee refunds, secondary/nested trigger dispatch, max_aa_responses limits, checkBalances/checkStorageSizes, or revertResponsesInCaches lets the attacker drain an AA balance, get a bounce that keeps the funds, or have a failed response committed anyway.",
    "Critical. An AA reaches a state or payout the script forbids, because oscript evaluation is wrong: Decimal arithmetic and toOscriptPrecision in formula/common.js, state var read/write and parseStateVar in storage.js, assignment and concurrent var updates, getter execution in executeGetter/callGetter, or data feed and balance lookups in formula/evaluation.js return a value that contradicts the validated definition, letting an attacker move another user's funds held by the AA.",
    "Critical. One posted unit or AA trigger makes honest nodes disagree, because validation or execution is non-deterministic across nodes: ojson/oscript parsing in formula/parse_ojson.js and the grammars, validation-time vs execution-time checks in aa_validation.js and formula/validation.js, cache-dependent reads in storage.js, or ordering assumptions in aa_composer.js make one node accept a unit or response another rejects, splitting the DAG.",
    "Critical. The main chain or stability decision can be steered or made inconsistent by an ordinary poster, because updateMainChain, advanceMcStability, determineIfStableInLaterUnits, findMinMcWitnessedLevel, best-parent and witnessed-level computation in main_chain.js, parent/skiplist checks in validation.js, or inclusion tests in graph.js let a crafted unit reverse a stable unit, stall stability advance, or make nodes compute different last stable units.",
    "Critical. A single crafted unit, asset definition or AA trigger permanently stops nodes from confirming new transactions, because writer.js saveJoint, main_chain.js stability advance, aa_composer.js trigger handling, mutex.js lock acquisition, or the unhandled-joint queue in joint_storage.js throws, deadlocks or leaves the DB in a state every restart re-enters, requiring a coordinated upgrade to recover.",
    "High. A victim accepts asset units that were never validly issued or loses control of funds they hold, because asset rules are bypassed: validateAssetDefinition and transfer/issue conditions in validation.js, cap and issuance checks, spender attestation, or private payment chain validation in indivisible_asset.js validatePrivatePayment/parsePrivatePaymentChain and divisible_asset.js validateDivisiblePrivatePayment lets an attacker hand a counterparty a forged or replayed private chain.",
    "High. A counterparty tricks a victim's wallet into authorizing or crediting something the user never approved, because messages from an arbitrary paired device are trusted: handling in device.js, cosigner and address-definition flows in wallet_defined_by_keys.js and wallet_defined_by_addresses.js, payment and contract handling in wallet.js, prosaic_contract.js, arbiter_contract.js, private_profile.js, signed-message checks in signed_message.js validateSignedMessage, or link parsing in uri.js.",
    "Critical/High blind spot. An ordinary unit poster, AA author, AA trigger sender, asset issuer, private-payment counterparty or paired device abuses an assumption ocore never wrote down: a value checked at validation time and trusted as already-checked at write or AA-execution time, a definition, asset or state var re-read after the check that authorized it, a limit enforced on one message type but not on its asset, private, AA-posted or multi-author twin, state carried across unit, mci, stability, upgrade-mci, cache or bounce boundaries that was only proven safe inside one of them, or an error path that commits partial state - yielding unauthorized spending, supply inflation, node disagreement, or a network that stops confirming transactions.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit and fuzzing questions for one ocore target.

    ```
    target_file format:
    "'File Name: aa_composer.js -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit questions for this exact ocore target:

    {target_file}

    Project focus:
    ocore is the Obyte DAG full-node library. Focus only on what an ordinary user reaches: posting a unit, spending outputs, address definitions and authentifiers, unit hashing and signatures, DAG parents/main-chain/stability, headers commissions and witnessing earnings, asset issuance and transfer conditions, private payment chains sent to a counterparty, Autonomous Agent definitions and triggers, oscript/ojson parsing and evaluation, data feeds and attestations read by AAs, and wallet/multisig/contract messages from a paired device.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact JS symbols (function, exported method, object field, constant) when possible.
    * Attacker is unprivileged only: any user who funds an address and posts signed units of any message type, defines and triggers Autonomous Agents, defines and issues assets, sends private payment chains or contract offers to a counterparty, or pairs a device with a victim wallet. They sign only for their own keys.
    * Attacker is NOT a witness, order provider, hub, relay, node operator, host or DB owner, or holder of another user's key. Never assume a malicious peer, malicious node, malicious hub, p2p/gossip/catchup/sync-message attacker, network-level DoS, leaked key, compromised host, non-default conf.js, or social engineering.
    * Out of scope, never ask about: p2p protocol and peer handling, hub/relay behaviour, catchup and light-client proof serving, witness-proof fetching, network-level flooding, TLS/websocket layer, CLI, logging, dependencies.
    * Ignore test files, mocks, docs, generated grammar output, and config-only findings.
    * Every question must describe a real unit, AA trigger, asset issuance, private payment chain or device message an attacker actually posts through a valid entrypoint. No generic unbounded-allocation, memory-growth, cache-size, or resource-exhaustion speculation; no "what if the input is huge" without a concrete posted payload and a concrete broken invariant.
    * Generate 40 to 80 high-signal questions.
    * At least 70% must target spending funds without the owner's keys, double-spending a stable output, supply inflation, draining an Autonomous Agent, honest nodes disagreeing on validity or stability, or the network permanently failing to confirm new units.
    * Every question must be testable by an ava unit test in test/, a validation test over a crafted joint, an aa_composer trigger test, or a local testnet run.
    * Avoid generic checklist questions and repeated root causes.

    Core invariants:
    * Authorization is exact: an output is spent only when authentifiers satisfy that address's definition, as of the definition active at the unit's last_ball_mci, over the exact unit hash that is stored.
    * Value is conserved: per asset and per unit, inputs equal outputs plus fees; commissions and witnessing earnings are attributed once; an AA never pays out more than it holds.
    * Determinism holds: every honest node validating the same joint reaches the same accept/reject, the same main chain and stability, and the same AA responses and state vars.
    * Finality is final: once a unit is stable its effects, balances and spent outputs never change, and no conflicting unit becomes stable.
    * Liveness of valid users: no posted unit, asset or AA trigger can permanently stop nodes from validating and confirming new units.

    Each question must include:
    1. target function/method;
    2. attacker action (a concrete unit, trigger, asset, private chain or device message: message type, fields, authentifiers);
    3. preconditions (addresses, balance, definitions, AAs and keys the attacker owns);
    4. execution sequence;
    5. invariant tested;
    6. scoped impact;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Function: symbol_or_method] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger EXECUTION_SEQUENCE, violating INVARIANT, causing scoped impact: SCOPE_IMPACT? Proof idea: ava unit/validation/aa_composer/testnet test PARAMETERS and assert AUTHORIZATION_EXACTNESS, VALUE_CONSERVATION, DETERMINISM, FINALITY, or USER_LIVENESS.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a focused ocore exploit-validation prompt.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: any user who funds an address and posts signed units, defines and triggers Autonomous Agents, defines and issues assets, sends private payment chains or contract offers to a counterparty, or pairs a device with a victim wallet. No witness, order provider, hub, relay, operator, host, DB, or foreign-key access.
- Reject malicious-peer, malicious-node, malicious-hub, p2p/gossip/catchup/sync, network-DoS, leaked-key, host-level, and misconfiguration-only paths.
- Reject light-client proof serving, witness-proof fetching, TLS/websocket, CLI, logging, dependency-only, and test/mock/docs/generated/config-only findings.
- Reject generic unbounded-allocation or resource-growth claims with no concrete posted payload and no broken invariant.
- This program pays High and Critical only. Focus on real chain impact: spending funds without the owner's keys, double-spending a stable output, supply inflation, permanent freezing or draining of Autonomous Agent funds, honest nodes disagreeing on validity or stability, or the network permanently unable to confirm new transactions.

## Validate
- Trace the exact reachable path from the attacker's unit, trigger, asset, private chain or device message into the affected function.
- Check whether authentifier and definition validation, unit size and fee checks, duplicate/double-spend detection, aa_validation limits, or existing error handling already stop it.
- Confirm the path is reachable on current mainnet constants and the active upgrade mci.
- Accept only concrete unauthorized spending, supply inflation, AA fund loss, stable-unit reversal, node disagreement, or a lasting inability to confirm new units.
- Require exact file/function support and a reproducible ava unit, validation, aa_composer, or local-testnet PoC.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[Code path, root cause, attacker payload, exploit flow, and why checks fail]

### Impact Explanation
[Concrete scoped impact and severity: Critical (loss or permanent freezing of funds, spending without the owner's keys, supply inflation, consensus divergence, network permanently unable to confirm transactions) or High (authorization bypass, corruption of unit, balance or AA state, or honest nodes unable to confirm new transactions for at least a day)]

### Likelihood Explanation
[Preconditions, addresses and balance needed, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[ava unit/validation/aa_composer/testnet test plan with expected assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for ocore.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope production repo context only. Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only analogs an unprivileged unit poster, AA author, AA trigger sender, asset issuer, private-payment counterparty or paired device can reach: unit validation, address definitions and authentifiers, hashing and signatures, DAG parents and stability, payment inputs/outputs and commissions, asset issuance and transfer conditions, private payment chains, AA definitions and triggers, oscript/ojson evaluation, data feeds, or wallet and contract message handling.
- Reject malicious-peer, malicious-node, malicious-hub, p2p/catchup/sync, network-DoS, leaked-key, operator-only, light-proof-serving, TLS, CLI, mocked-only paths, dependency-only bugs, and no-impact analogs.
- Medium , High and Critical only; no low, or resource-only analogs.

## Validate
- Map the bug class to the strongest reachable ocore path from a single posted unit, trigger, asset, private chain or device message.
- Prove root cause with exact file/function support.
- Accept only concrete unauthorized spending, double-spend of a stable output, supply inflation, AA fund loss or freezing, node disagreement on validity or stability, or a network unable to confirm new units.

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
    Generate a strict bounty-style validation prompt for ocore security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- This program pays High and Critical only; reject low, medium, informational, best-practice, and resource-only reports.
- Reject malicious-peer, malicious-node, malicious-hub, p2p/gossip/catchup/sync, network-level DoS, light-client proof serving, witness-proof fetching, TLS/websocket, CLI, logging, dependency-only, docs/style, generated-file, and test/mock/config-only issues.
- Reject if the exploit needs witness, order-provider, hub, relay, operator, host, database, or privileged access, another user's key, victim social engineering, a non-default conf.js, or anything outside what an unprivileged user can put in a posted unit, AA trigger, asset, private payment chain, or device message.
- Reject 51%-style majority-witness attacks, sybil and centralization claims, and third-party oracle data being wrong without a manipulation path.
- Reject if the bug was fixed, acknowledged, or publicly disclosed already, per the eligibility rules.
- A valid report must be triggerable by an unprivileged unit poster, AA author, AA trigger sender, asset issuer, private-payment counterparty or paired device, unless the claim proves escalation from that starting point.
- The final impact must map to an in-scope category: Critical - direct loss of funds, permanent freezing of funds, spending or executing transactions from another user's address without their private keys, supply inflation, double-spending a stable output, consensus divergence between honest nodes, or the network permanently unable to confirm new transactions; High - authorization bypass, corruption of unit, balance, asset or AA state, or honest nodes unable to process valid transactions for at least a day.
- Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken authorization, value-conservation, determinism, finality, or user-liveness invariant.
3. Reachable exploit path: preconditions (attacker-owned addresses, balance, definitions, AAs) -> posted unit, trigger, asset, private chain or device message -> trigger -> bad result.
4. Existing authentifier and definition validation, size and fee checks, double-spend detection, aa_validation limits, and error handling reviewed and shown insufficient.
5. Concrete in-scope High/Critical impact with realistic likelihood.
6. Reproducible proof path: ava unit PoC, validation test over a crafted joint, aa_composer trigger test, or exact steps on a local testnet.
7. No obvious rejection reason from SECURITY.md, known issues, privilege assumptions, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Can an ordinary user trigger this by posting a unit, trigger, asset, private chain or device message, without witness, hub, operator, host, or foreign-key access?
- Does the code actually behave as claimed under current mainnet constants and the active upgrade mci?
- Is the impact caused by this code, not by a malicious peer, hub, or dependency?
- Is the theft, inflation, divergence, or halt concrete rather than hypothetical?
- Would an Obyte triager on Immunefi accept the proof-of-concept?
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
[Concrete in-scope impact, severity rationale, and Obyte bounty category]

## Likelihood Explanation
[Attacker capability, addresses and balance required, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or ava unit/validation/aa_composer/testnet test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
