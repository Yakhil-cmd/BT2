import json
import os

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 25
SOURCE_REPO = "starkware-libs/sequencer"
REPO_NAME = "sequencer"
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
    "crates/apollo_class_manager/src/class_manager.rs",
    "crates/apollo_class_manager/src/class_storage.rs",
    "crates/apollo_compile_to_casm/src/compiler.rs",
    "crates/apollo_compile_to_native/src/compiler.rs",
    "crates/apollo_gateway/src/gateway.rs",
    "crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs",
    "crates/apollo_gateway/src/state_reader.rs",
    "crates/apollo_gateway/src/stateful_transaction_validator.rs",
    "crates/apollo_gateway/src/stateless_transaction_validator.rs",
    "crates/apollo_gateway/src/sync_state_reader.rs",
    "crates/apollo_gateway_types/src/deprecated_gateway_error.rs",
    "crates/apollo_gateway_types/src/gateway_types.rs",
    "crates/apollo_http_server/src/deprecated_gateway_transaction.rs",
    "crates/apollo_http_server/src/http_server.rs",
    "crates/apollo_l1_gas_price/src/eth_to_strk_oracle.rs",
    "crates/apollo_l1_gas_price/src/l1_gas_price_provider.rs",
    "crates/apollo_l1_gas_price/src/l1_gas_price_scraper.rs",
    "crates/apollo_l1_provider/src/l1_provider.rs",
    "crates/apollo_l1_provider/src/transaction_manager.rs",
    "crates/apollo_mempool/src/fee_transaction_queue.rs",
    "crates/apollo_mempool/src/fifo_transaction_queue.rs",
    "crates/apollo_mempool/src/mempool.rs",
    "crates/apollo_mempool/src/transaction_pool.rs",
    "crates/apollo_mempool/src/transaction_queue_trait.rs",
    "crates/apollo_mempool/src/utils.rs",
    "crates/apollo_mempool_p2p/src/propagator/mod.rs",
    "crates/apollo_mempool_p2p/src/runner/mod.rs",
    "crates/apollo_rpc/src/api.rs",
    "crates/apollo_rpc/src/middleware.rs",
    "crates/apollo_rpc/src/pending.rs",
    "crates/apollo_rpc/src/v0_8/api/api_impl.rs",
    "crates/apollo_rpc/src/v0_8/broadcasted_transaction.rs",
    "crates/apollo_rpc/src/v0_8/deprecated_contract_class.rs",
    "crates/apollo_rpc/src/v0_8/error.rs",
    "crates/apollo_rpc/src/v0_8/execution.rs",
    "crates/apollo_rpc/src/v0_8/state.rs",
    "crates/apollo_rpc/src/v0_8/transaction.rs",
    "crates/apollo_rpc/src/v0_8/write_api_error.rs",
    "crates/apollo_rpc/src/v0_8/write_api_result.rs",
    "crates/apollo_rpc_execution/src/execution_utils.rs",
    "crates/apollo_rpc_execution/src/objects.rs",
    "crates/apollo_rpc_execution/src/state_reader.rs",
    "crates/apollo_signature_manager/src/blake_utils.rs",
    "crates/apollo_signature_manager/src/signature_manager.rs",
    "crates/apollo_state_reader/src/apollo_state.rs",
    "crates/apollo_state_reader/src/lib.rs",
    "crates/apollo_transaction_converter/src/transaction_converter.rs",
    "crates/blockifier/src/blockifier.rs",
    "crates/blockifier/src/blockifier/block.rs",
    "crates/blockifier/src/blockifier/config.rs",
    "crates/blockifier/src/blockifier/stateful_validator.rs",
    "crates/blockifier/src/blockifier/transaction_executor.rs",
    "crates/blockifier/src/blockifier_versioned_constants.rs",
    "crates/blockifier/src/bouncer.rs",
    "crates/blockifier/src/context.rs",
    "crates/blockifier/src/execution/call_info.rs",
    "crates/blockifier/src/execution/casm_hash_estimation.rs",
    "crates/blockifier/src/execution/common_hints.rs",
    "crates/blockifier/src/execution/contract_address.rs",
    "crates/blockifier/src/execution/contract_class.rs",
    "crates/blockifier/src/execution/deprecated_entry_point_execution.rs",
    "crates/blockifier/src/execution/deprecated_syscalls/deprecated_syscall_executor.rs",
    "crates/blockifier/src/execution/deprecated_syscalls/hint_processor.rs",
    "crates/blockifier/src/execution/entry_point.rs",
    "crates/blockifier/src/execution/entry_point_execution.rs",
    "crates/blockifier/src/execution/execution_utils.rs",
    "crates/blockifier/src/execution/native/contract_class.rs",
    "crates/blockifier/src/execution/native/entry_point_execution.rs",
    "crates/blockifier/src/execution/native/syscall_handler.rs",
    "crates/blockifier/src/execution/native/utils.rs",
    "crates/blockifier/src/execution/secp.rs",
    "crates/blockifier/src/execution/syscalls/common_syscall_logic.rs",
    "crates/blockifier/src/execution/syscalls/hint_processor.rs",
    "crates/blockifier/src/execution/syscalls/syscall_base.rs",
    "crates/blockifier/src/execution/syscalls/syscall_executor.rs",
    "crates/blockifier/src/execution/syscalls/vm_syscall_utils.rs",
    "crates/blockifier/src/fee/eth_gas_constants.rs",
    "crates/blockifier/src/fee/fee_checks.rs",
    "crates/blockifier/src/fee/fee_utils.rs",
    "crates/blockifier/src/fee/gas_usage.rs",
    "crates/blockifier/src/fee/receipt.rs",
    "crates/blockifier/src/fee/resources.rs",
    "crates/blockifier/src/state/cached_state.rs",
    "crates/blockifier/src/state/compiled_class_hash_migration.rs",
    "crates/blockifier/src/state/contract_class_manager.rs",
    "crates/blockifier/src/state/global_cache.rs",
    "crates/blockifier/src/state/native_class_manager.rs",
    "crates/blockifier/src/state/state_api.rs",
    "crates/blockifier/src/state/state_reader_and_contract_manager.rs",
    "crates/blockifier/src/state/stateful_compression.rs",
    "crates/blockifier/src/transaction/account_transaction.rs",
    "crates/blockifier/src/transaction/l1_handler_transaction.rs",
    "crates/blockifier/src/transaction/objects.rs",
    "crates/blockifier/src/transaction/transaction_execution.rs",
    "crates/blockifier/src/transaction/transactions.rs",
    "crates/native_blockifier/src/py_block_executor.rs",
    "crates/native_blockifier/src/py_declare.rs",
    "crates/native_blockifier/src/py_deploy_account.rs",
    "crates/native_blockifier/src/py_invoke_function.rs",
    "crates/native_blockifier/src/py_l1_handler.rs",
    "crates/native_blockifier/src/py_validator.rs",
    "crates/starknet_api/src/contract_class.rs",
    "crates/starknet_api/src/contract_class/compiled_class_hash.rs",
    "crates/starknet_api/src/core.rs",
    "crates/starknet_api/src/executable_transaction.rs",
    "crates/starknet_api/src/execution_resources.rs",
    "crates/starknet_api/src/rpc_transaction.rs",
    "crates/starknet_api/src/state.rs",
    "crates/starknet_api/src/transaction.rs",
    "crates/starknet_api/src/transaction/constants.rs",
    "crates/starknet_api/src/transaction/fields.rs",
    "crates/starknet_api/src/transaction_hash.rs",
]

target_scopes = [
    "Critical. Unprivileged-user-triggered account transaction validation, nonce, chain id, signature, resource bounds, tip, fee token, paymaster, or account deployment bug admits an unauthorized or invalid Starknet transaction.",
    "Critical. Unprivileged-user-triggered execution, syscall, class declaration, library call, replace-class, storage, event, L1 message, or revert-handling bug changes state, receipts, events, messages, or class hashes incorrectly.",
    "Critical. Unprivileged-user-triggered fee, gas, bouncer, L1 gas price, resource accounting, refund, or balance-charge bug undercharges, over-refunds, mints/burns, or misorders economic effects.",
    "Critical. Unprivileged-user-triggered class compilation, CASM/native cache, compiled class hash, Sierra/deprecated class conversion, or contract-class manager bug executes stale, wrong, or unauthorized code.",
    "High. Unprivileged-user-triggered gateway, RPC, transaction converter, mempool, or mempool-p2p path accepts transactions canonical validation must reject, or rejects valid transactions before sequencing.",
    "High. Unprivileged-user-triggered RPC execution/view path returns verified-looking but wrong block, state, class, storage, fee estimate, simulation, trace, or pending value.",
    "High. Unprivileged-user-triggered signature manager, account abstraction, hash calculation, or transaction type conversion bug verifies the wrong signer, transaction hash, or executable transaction.",
]

EXECUTION_ALLOWED_IMPACT_SCOPE = """## Allowed Impact Scope
Only these impacts are valid:
- Critical. Invalid or unauthorized Starknet transaction accepted through account validation, signature, nonce, chain id, fee/resource bound, paymaster, or account-deployment logic.
- Critical. Wrong state, receipt, event, L1 message, class hash, storage value, or revert result from blockifier/syscall/execution logic for accepted input.
- Critical. Incorrect fee, gas, bouncer, resource accounting, refund, balance, or L1 gas price effect with economic impact.
- Critical. Wrong compiled class, CASM/native artifact, class hash, or contract code selected for execution.
- High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.
- High. RPC execution, fee estimation, tracing, simulation, or pending view returns an authoritative-looking wrong value.
- High. Transaction conversion or signature/hash logic binds the wrong signer, hash, type, or executable payload."""

SMART_AUDIT_PIVOTS = """## Sequencer-Specific Audit Pivots
- Gateway stateless path: `StatelessTransactionValidator::validate` checks contract address, empty `account_deployment_data`/`paymaster_data`, resource bounds, calldata+proof-facts length, signature/proof size, DA modes forced to L1, client-side proving allowance/consistency, Sierra version, class object size, and sorted unique entry points. Ask where later conversion/execution interprets a field differently.
- Gateway stateful path: `extract_state_nonce_and_run_validations` gets latest nonce, checks resource bounds against previous block L2 gas price, applies nonce gap rules, calls mempool validation, may `skip_stateful_validations` for deploy-account plus invoke UX, then runs blockifier validation with `block_number.unchecked_next()`, `strict_nonce_check=false`, and CASM hash migration disabled.
- Blockifier pre/execution path: `AccountTransaction::perform_pre_validation_stage` calls `handle_nonce`, `check_fee_bounds`, `verify_can_pay_committed_bounds`, and `validate_proof_facts`; execution then handles validation entry point, syscall state changes, fee transfer, revert info, receipt output, and concurrency fee-transfer balance writes.
- Conversion/class/proof path: `TransactionConverter::convert_rpc_tx_to_internal` calculates tx hash with `chain_id`, validates `compiled_class_hash` against class manager output, calculates deploy-account address, extracts proof facts/proof, and later builds executable transactions from stored Sierra/executable classes. Look for mismatch between accepted RPC data and executable payload."""


def question_generator(target_file: str) -> str:
    """
    Generate execution, admission, and ledger-safety audit questions for one target.
    """

    prompt = f"""
    Generate execution/admission security questions for this exact Starknet Sequencer target:

    {target_file}

    Lens:
    Focus on user-submitted Starknet transactions and contract execution. Look for bugs in validation, account abstraction, nonces, signatures, resource bounds, fees, gas prices, block context, syscalls, class declaration/compilation, state reads/writes, receipts/events/messages, simulation, and mempool/gateway/RPC admission.

    Required impact gate:
    {EXECUTION_ALLOWED_IMPACT_SCOPE}

    {SMART_AUDIT_PIVOTS}

    Rules:
    * Treat `File Name:` as the exact file/module and `Scope:` as the only impact.
    * Assume repo context is accessible; do not ask for code.
    * Attacker is an ordinary account holder, contract deployer/caller, public RPC client, or low-trust peer relaying public transactions.
    * Attacker may control their signed transaction fields, calldata, contract code, declared classes, paymaster/resource-bound fields, L1 handler payloads only if publicly triggerable, and RPC simulation/query inputs.
    * Do not assume sequencer operator, validator, privileged relayer, oracle, node admin, database, or deployment control.
    * Do not generate questions for malicious-peer-only behavior where bad data is rejected, ignored, disconnected, retried, rate-limited, or only wastes resources.
    * Exclude tests, mocks, benches, generated data, local tooling, ordinary crash/DoS, unbounded CPU/memory/disk/cache/queue growth, OOM, leaks, performance-only degradation, logs, style, and dependency-only behavior unless one allowed impact above is concretely reached.
    * Generate 16 to 22 high-signal questions. Avoid generic checklist items and repeated fee/signature/cache root causes.
    * Name the exact value at risk: nonce, fee, gas usage, resource bound, account balance, storage key/value, class hash, compiled class hash, contract address, event, receipt, L1 message, transaction hash, admission decision, simulation result, or pending state.
    * Every question must be testable with a Rust unit/property/fuzz test or focused local reproducer.

    Each question must include target symbol, attacker-controlled field/input, required account/block state, call path, invariant, corrupted value, scoped impact, and proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Symbol: symbol_or_module] Can attacker-controlled FIELD under STATE force CALL_PATH to violate LEDGER_OR_ADMISSION_INVARIANT, corrupting EXACT_VALUE with scoped impact SCOPE_IMPACT? Proof idea: build a Rust execution/admission/property reproducer over PARAMETERS and assert EXPECTED_ACCOUNTING_OR_AUTHORIZATION_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused execution/admission question validation prompt.
    """
    return f"""# EXECUTION AND ADMISSION QUESTION REVIEW

## Exploit Question
{question}

## Boundary
Audit only production Sequencer files listed in `scope_files`. Ignore tests, mocks, fixtures, generated data, docs, benches, scripts, deployments, and local tools.

## Goal
Determine whether the question can lead to a real issue in transaction validation, account abstraction, execution, fees, class compilation, state mutation, RPC simulation, or mempool/gateway admission. The path must start from unprivileged public inputs.

Reject privileged operator/admin/validator/relayer/oracle assumptions. Prefer #NoVulnerability unless the exact corrupted nonce, fee, balance, state, class, receipt, event, message, hash, simulation, or admission value is concrete.

## Required Impact Scope
{EXECUTION_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

## Checks
1. Identify the production entrypoint and target symbol.
2. Trace attacker-controlled fields through validators, converters, blockifier, state readers, caches, and storage.
3. Check signatures, chain id, nonces, resource bounds, fees, class hashes, account deployment, syscall permissions, revert semantics, and pending-state selection.
4. Reject if canonical validation, execution rollback, fee charging, cache keys, or state isolation already prevents it.

## Fast Rejections
- Requires sequencer/operator/admin/validator/relayer/oracle/database privileges.
- Only malicious peer noise, rejected bad peer data, crash, DoS, unbounded CPU/memory/disk/cache/queue growth, OOM, leaks, performance-only degradation, logging, metrics, or best practice.
- Dependency-only or downstream misuse outside this repo's production API.
- No exact corrupted ledger/execution/admission value or no unprivileged trigger.

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
    Generate a cross-project analog scan prompt for execution/admission issues.
    """
    prompt = f"""# EXECUTION AND ADMISSION ANALOG SCAN

## External Report
{report}

## Task
Use the external report only as a seed. Search production `scope_files` for a Sequencer-native analog in account transaction validation, signatures, nonces, fees, resource bounds, syscalls, class compilation, state mutation, receipts/events/messages, RPC simulation, or mempool/gateway admission.

## Required Impact Scope
{EXECUTION_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

Report only if this repo has its own reachable root cause, unprivileged trigger, broken invariant, exact corrupted value, and matching impact above. Reject privileged operations, resource-only issues, unbounded growth, malicious-peer-only noise, dependency-only behavior, and non-production files.

## Work Plan
1. Translate the external bug into an authorization, accounting, state, code-identity, or admission invariant.
2. Map it to exact production symbols.
3. Trace attacker-controlled fields through validation/execution.
4. Identify the wrong nonce, fee, balance, storage value, class hash, receipt, event, L1 message, transaction hash, simulation result, or admission decision.
5. Reject if existing guards preserve the invariant.

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
    Generate a strict execution/admission validation prompt.
    """
    prompt = f"""# EXECUTION AND ADMISSION VALIDATION

## Security Claim
{report}

## Validation Rules
- Validate only this claim against production Sequencer files in `scope_files`.
- A valid issue must be reachable through unprivileged transaction, contract, class, RPC, simulation, or public mempool/gateway input.
- Reject privileged sequencer/operator/admin/validator/relayer/oracle/database assumptions, tests/mocks/generated files, crash/DoS, unbounded CPU/memory/disk/cache/queue growth, OOM, leaks, resource-only issues, logs, style, dependency-only behavior, malicious-peer-only behavior, and downstream misuse.
- The final impact must match one allowed scope below and name the exact corrupted execution/admission value.

{EXECUTION_ALLOWED_IMPACT_SCOPE}

{SMART_AUDIT_PIVOTS}

## Required Checks
1. Exact file/function/line references.
2. Broken authorization, accounting, execution, state isolation, code identity, or admission invariant.
3. Exploit path: preconditions -> attacker field -> call path -> bad value.
4. Existing guards shown insufficient.
5. Reproducible Rust test, property/fuzz test, or focused local reproducer.

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary]

## Finding Description
[Code path, root cause, exploit flow, and failed guards]

## Impact Explanation
[Concrete allowed impact and severity]

## Likelihood Explanation
[Attacker capability and conditions]

## Recommendation
[Specific fix]

## Proof of Concept
[Minimal reproducible steps or test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
