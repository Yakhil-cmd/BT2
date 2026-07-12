import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the path from https://github.com/crypto-org-chain/cronos
SOURCE_REPO = "crypto-org-chain/cronos"
# todo: the name of the repository
REPO_NAME = "cronos"
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
    "app/app.go",
    "app/block_address.go",
    "app/export.go",
    "app/forks.go",
    "app/legacy.go",
    "app/mempool/decoder_cache.go",
    "app/mempool/encoder_cache.go",
    "app/mempool/gossip.go",
    "app/mempool/helpers.go",
    "app/mempool/manager.go",
    "app/mempool/preverify.go",
    "app/mempool/reap.go",
    "app/mempool/recheck_worker.go",
    "app/prefix.go",
    "app/proposal.go",
    "app/state.go",
    "app/storeloader.go",
    "app/unblockable.go",
    "app/upgrades.go",
    "app/versiondb.go",
    "app/versiondb_placeholder.go",
    "contracts/src/ModuleCRC20.sol",
    "contracts/src/ModuleCRC20Proxy.sol",
    "contracts/src/ModuleCRC20ProxyAuthority.sol",
    "contracts/src/ModuleCRC21.sol",
    "proto/cronos/cronos.proto",
    "proto/cronos/genesis.proto",
    "proto/cronos/query.proto",
    "proto/cronos/tx.proto",
    "proto/e2ee/genesis.proto",
    "proto/e2ee/query.proto",
    "proto/e2ee/tx.proto",
    "x/cronos/events/bindings/src/Bank.sol",
    "x/cronos/events/bindings/src/CosmosTypes.sol",
    "x/cronos/events/bindings/src/ICA.sol",
    "x/cronos/events/bindings/src/ICACallback.sol",
    "x/cronos/events/bindings/src/Relayer.sol",
    "x/cronos/events/bindings/src/RelayerFunctions.sol",
    "x/cronos/events/decoders.go",
    "x/cronos/events/event.go",
    "x/cronos/events/events.go",
    "x/cronos/events/types/types.go",
    "x/cronos/exported/exported.go",
    "x/cronos/genesis.go",
    "x/cronos/keeper/evm.go",
    "x/cronos/keeper/evm_hooks.go",
    "x/cronos/keeper/evmhandlers/send_cro_to_ibc.go",
    "x/cronos/keeper/evmhandlers/send_to_account.go",
    "x/cronos/keeper/evmhandlers/send_to_ibc.go",
    "x/cronos/keeper/evmhandlers/send_to_ibc_v2.go",
    "x/cronos/keeper/grpc_query.go",
    "x/cronos/keeper/ibc.go",
    "x/cronos/keeper/keeper.go",
    "x/cronos/keeper/migrations.go",
    "x/cronos/keeper/msg_server.go",
    "x/cronos/keeper/params.go",
    "x/cronos/keeper/permissions.go",
    "x/cronos/keeper/precompiles/bank.go",
    "x/cronos/keeper/precompiles/base_contract.go",
    "x/cronos/keeper/precompiles/ica.go",
    "x/cronos/keeper/precompiles/interface.go",
    "x/cronos/keeper/precompiles/relayer.go",
    "x/cronos/keeper/precompiles/utils.go",
    "x/cronos/middleware/conversion_middleware.go",
    "x/cronos/migrations/v2/migrate.go",
    "x/cronos/module.go",
    "x/cronos/proposal_handler.go",
    "x/cronos/rpc/api.go",
    "x/cronos/types/codec.go",
    "x/cronos/types/contracts.go",
    "x/cronos/types/errors.go",
    "x/cronos/types/events.go",
    "x/cronos/types/genesis.go",
    "x/cronos/types/interfaces.go",
    "x/cronos/types/keys.go",
    "x/cronos/types/messages.go",
    "x/cronos/types/params.go",
    "x/cronos/types/proposal.go",
    "x/cronos/types/query.go",
    "x/cronos/types/tracer.go",
    "x/cronos/types/types.go",
    "x/e2ee/autocli.go",
    "x/e2ee/keeper/keeper.go",
    "x/e2ee/keyring/keyring.go",
    "x/e2ee/module.go",
    "x/e2ee/types/codec.go",
    "x/e2ee/types/genesis.go",
    "x/e2ee/types/keys.go",
    "x/e2ee/types/msg.go",
]

target_scopes = [
    "Critical: Unauthorized mint, burn, transfer, bridge, conversion, escrow release, or balance/accounting change for CRO, IBC vouchers, CRC20, CRC21, ERC20, or precompile-controlled assets",
    "Critical: Consensus divergence, deterministic state mismatch, invalid block acceptance, or chain halt triggered by an unprivileged transaction, EVM log, precompile call, IBC packet, proposal path, or mempool/proposal interaction",
    "High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks",
    "High: Corruption of token mappings, denom/contract binding, IBC channel/accounting state, EVM receipt/log processing, precompile state, or e2ee key/message state with direct security impact",
    "High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions",
]


def question_generator(target_file: str) -> str:
    """
    Generate exploit-focused audit + fuzzing questions for one Cronos target.

    ```
    target_file format:
    "'File Name: x/cronos/keeper/msg_server.go -> Scope: High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks'"
    ```
    """

    prompt = f"""
    ```

    Generate exploit-focused security audit and fuzzing questions for this exact Cronos target:

    {target_file}

    Project context:
    Cronos is a Cosmos SDK/Ethermint EVM chain. In-scope production logic includes app wiring, proposal/mempool behavior, Cronos module messages, token mapping and conversions, IBC/EVM bridge handlers, EVM post-tx log hooks, native precompiles, CRC20/CRC21 contracts, params/permissions/block-list updates, e2ee key/message state, migrations, and proto-defined transaction/query surfaces.

    Core invariants:
    * Asset accounting across bank, EVM, module accounts, IBC vouchers, CRC20/CRC21, conversions, and precompiles must remain conserved and authorization-bound.
    * EVM hooks, precompiles, IBC handlers, and msg servers must not let unprivileged callers bypass admin/gov/permission checks.
    * Proposal, mempool, recheck, upgrades, migrations, and app initialization must be deterministic for honest validators.
    * Token mappings, denoms, contract addresses, receipts/logs, e2ee keys, params, and block-list state must remain canonical and unforgeable.

    Rules:
    * Treat `File Name:` as the exact file/module and `Scope:` as the only impact to target.
    * Assume full repo context is accessible; do not ask for code or say files are missing.
    * Generate 20 to 30 high-signal questions focused only on Critical or High impact.
    * At least 70% must be multi-step flow, invariant, fuzz, accounting, state-transition, or cross-module questions.
    * Every question must be testable by PoC, unit test, fuzz test, invariant test, differential test, or local integration test.
    * Avoid generic checklists, repeated root causes, best-practice items, and low/medium findings.
    * Do not generate resource-exhaustion questions unless the realistic result is consensus failure, chain halt, or long-lived inability to process valid protocol actions.
    * Attacker is unprivileged: external tx sender, EVM caller, malicious contract, IBC counterparty/relayer, RPC/mempool peer, proposer, or message submitter within normal protocol rules.
    * Exclude leaked keys, validator host compromise, admin/gov compromise, dependency compromise, local misconfiguration, phishing, malicious app changes, tests, mocks, generated files, scripts, and docs.

    High-value attack surfaces:
    * MsgConvertVouchers, MsgTransferTokens, MsgUpdateTokenMapping, MsgUpdatePermissions, MsgStoreBlockList, params and permission checks.
    * EVM log handlers, receipt mutation, bridge/conversion events, precompile ABI decoding, caller/address normalization, and revert/error semantics.
    * IBC denom/channel/account validation, token mapping canonicalization, module-account escrow, and bank/EVM balance synchronization.
    * Mempool admission, CheckTx/ReCheck, proposal filtering, tx decoding/canonical bytes, replay/order dependence, and deterministic app state.
    * CRC20/CRC21/proxy authority contracts, native module bindings, upgrade/migration state transforms, e2ee key registration and encrypted message storage.

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
    Generate a focused Cronos exploit-question validation prompt.
    """
    return f"""# QUESTION SCAN PROMPT

## Exploit Question
{question}

## Scope Rules
- Audit only production Cronos code in scope: app/mempool/proposal logic, x/cronos keeper/types/events/precompiles/EVM hooks/IBC handlers, CRC20/CRC21 contracts, proto schemas, and x/e2ee state logic.
- Ignore tests, docs, mocks, generated files, scripts, local fixtures, vendored code, package metadata, and operator-only local setup unless the claim proves direct Critical/High chain impact.
- This protocol pays only High and Critical issues; reject low, medium, best-practice, and pure resource-exhaustion reports.

## Objective
Decide whether the question leads to a real, reachable Cronos vulnerability.
The attacker must be unprivileged and enter through a transaction, EVM call/log, precompile, IBC flow, RPC/mempool path, proposal path, or message validation path implemented in this repo.
Prefer #NoVulnerability unless the path is concrete, local-testable, and bounty-grade.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized mint, burn, transfer, bridge, conversion, escrow release, or balance/accounting change for CRO, IBC vouchers, CRC20, CRC21, ERC20, or precompile-controlled assets
- Critical: Consensus divergence, deterministic state mismatch, invalid block acceptance, or chain halt triggered by an unprivileged transaction, EVM log, precompile call, IBC packet, proposal path, or mempool/proposal interaction
- High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks
- High: Corruption of token mappings, denom/contract binding, IBC channel/accounting state, EVM receipt/log processing, precompile state, or e2ee key/message state with direct security impact
- High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions

## Method
1. Trace the attacker-controlled entrypoint.
2. Map it to exact production Cronos files/functions.
3. Check guards for signer, admin/gov authority, permissions, denom/address validation, ABI/proto decoding, IBC/channel checks, EVM revert handling, balance conservation, and deterministic execution.
4. Prove root cause with file/function/line references and a reproducible PoC or test plan.
5. Reject if existing validation prevents the exploit or the final impact is not one allowed High/Critical impact.

## Reject Immediately
- Requires leaked keys, validator/admin/gov compromise, trusted host compromise, dependency compromise, broken cryptography, phishing, malicious integrator behavior, or unsupported external assumptions.
- Only affects tests, docs, configs, scripts, mocks, generated code, local fixtures, CLI ergonomics, logs, observability, or non-security correctness.
- External dependency behavior is the only cause.
- Impact is only rejected tx, harmless revert, local misconfiguration, temporary spam, theoretical risk, or unbounded resource use without Critical/High protocol impact.

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
    Generate a short cross-project analog scan prompt for Cronos.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Access Rules (Strict)
- Treat production Cronos files in the provided scope as accessible context.
- Do not claim missing/inaccessible files.
- Do not scan tests, docs, build files, generated files, mocks, scripts, fixtures, vendored code, package metadata, or CLI-only behavior as audited targets.
- Only High and Critical protocol/security impacts are payable; do not report medium/low/resource-only analogs.

## Objective
Use the external report's vulnerability class only as a hint.
Find an analog only if Cronos has its own reachable root cause in app/mempool/proposal logic, x/cronos messages/keeper/EVM hooks/precompiles/IBC handlers, CRC20/CRC21 contracts, proto-defined tx surfaces, or x/e2ee state logic.
The attacker must be unprivileged and the impact must match the allowed Cronos impacts below.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized mint, burn, transfer, bridge, conversion, escrow release, or balance/accounting change for CRO, IBC vouchers, CRC20, CRC21, ERC20, or precompile-controlled assets
- Critical: Consensus divergence, deterministic state mismatch, invalid block acceptance, or chain halt triggered by an unprivileged transaction, EVM log, precompile call, IBC packet, proposal path, or mempool/proposal interaction
- High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks
- High: Corruption of token mappings, denom/contract binding, IBC channel/accounting state, EVM receipt/log processing, precompile state, or e2ee key/message state with direct security impact
- High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions

## Method
1. Classify the external bug class: auth bypass, accounting bug, bridge/IBC flaw, EVM/precompile bug, consensus nondeterminism, mempool/proposal interaction, migration/upgrade bug, or state corruption.
2. Map only to exact Cronos production files/functions.
3. Prove attacker path, missing/insufficient guard, and exact High/Critical impact.
4. Reject if Cronos validation blocks it or the analogy is only superficial.

## Disqualify Immediately
- No reachable unprivileged entry path.
- Requires leaked keys, admin/gov/validator compromise, host compromise, dependency compromise, cryptographic break, or unsupported assumptions.
- Test/docs/config/build/generated/mock/local-only issue.
- Impact is temporary spam, logging, observability, CLI behavior, rejected tx, harmless revert, non-security correctness, or theory without protocol impact.

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
    Generate a strict Cronos bounty-style validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim against Cronos production code and SECURITY.md.
- Do not invent a new vulnerability or upgrade severity unless the evidence proves it.
- This protocol pays only High and Critical issues; reject low, medium, informational, best-practice, resource-only, and speculative reports.
- A valid report must be triggerable by an unprivileged tx sender, EVM caller/contract, IBC counterparty/relayer, mempool/RPC peer, proposer, or message submitter through code in this repo.
- Reject admin/gov/validator-key compromise, leaked keys, host compromise, dependency-only behavior, cryptographic breaks, phishing, victim mistakes, malicious integrator behavior, local misconfiguration, and unsupported protocol assumptions.

## In-Scope Protocol Areas
- Cronos app wiring, upgrades, migrations, proposal handling, mempool admission/recheck, and deterministic state transitions.
- x/cronos messages, params, permissions, token mapping, conversions, IBC handlers, EVM hooks, native precompiles, event decoding, and receipt/log processing.
- CRC20/CRC21/proxy contracts and Solidity bindings used by module/precompile flows.
- x/e2ee key/message state where a direct High/Critical security impact is proven.
- Proto-defined tx/query surfaces only when they enable a production exploit path.

Reject tests, docs, mocks, generated files, scripts, configs, local fixtures, vendored libraries, CLI-only behavior, and non-security correctness unless the claim proves direct High/Critical chain impact.

## Allowed Impact Scope
Only these impacts are valid:
- Critical: Unauthorized mint, burn, transfer, bridge, conversion, escrow release, or balance/accounting change for CRO, IBC vouchers, CRC20, CRC21, ERC20, or precompile-controlled assets
- Critical: Consensus divergence, deterministic state mismatch, invalid block acceptance, or chain halt triggered by an unprivileged transaction, EVM log, precompile call, IBC packet, proposal path, or mempool/proposal interaction
- High: Bypass of Cronos admin, governance authority, permission, token-mapping, bridge, block-list, or module-account authorization checks
- High: Corruption of token mappings, denom/contract binding, IBC channel/accounting state, EVM receipt/log processing, precompile state, or e2ee key/message state with direct security impact
- High: Permanent or long-lived inability for honest users or validators to process valid transactions, bridge/conversion flows, precompile calls, IBC transfers, or block proposals under normal network assumptions

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line/code references.
2. Clear root cause and broken authorization/accounting/state/consensus/IBC/EVM/precompile invariant.
3. Reachable exploit path: preconditions -> attacker action -> trigger -> bad result.
4. Existing guards reviewed and shown insufficient.
5. Concrete allowed High/Critical impact with realistic likelihood.
6. Reproducible proof path: unit PoC, deterministic integration test, invariant test, fuzz test, fork test, or exact local steps.
7. No rejection reason from SECURITY.md, privileges, scope exclusions, or known intended behavior.

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
[Concrete allowed Cronos security impact and severity rationale]

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
