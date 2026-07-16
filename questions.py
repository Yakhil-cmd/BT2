import json
import os

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 50
SOURCE_REPO = "near/nearcore"
REPO_NAME = "nearcore"
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
    "chain/chain/src/approval_verification.rs",
    "chain/chain/src/block_processing_utils.rs",
    "chain/chain/src/chain.rs",
    "chain/chain/src/chain_update.rs",
    "chain/chain/src/doomslug.rs",
    "chain/chain/src/lightclient.rs",
    "chain/chain/src/missing_chunks.rs",
    "chain/chain/src/orphan.rs",
    "chain/chain/src/pending.rs",
    "chain/chain/src/resharding/flat_storage_resharder.rs",
    "chain/chain/src/resharding/manager.rs",
    "chain/chain/src/resharding/migrations.rs",
    "chain/chain/src/resharding/resharding_actor.rs",
    "chain/chain/src/resharding/trie_state_resharder.rs",
    "chain/chain/src/runtime/mod.rs",
    "chain/chain/src/runtime/signer_overlay.rs",
    "chain/chain/src/runtime/trie_update_wrapper.rs",
    "chain/chain/src/sharding.rs",
    "chain/chain/src/signature_verification.rs",
    "chain/chain/src/spice/block_application.rs",
    "chain/chain/src/spice/chain.rs",
    "chain/chain/src/spice/chunk_application.rs",
    "chain/chain/src/spice/chunk_validation.rs",
    "chain/chain/src/spice/core.rs",
    "chain/chain/src/state_sync/adapter.rs",
    "chain/chain/src/state_sync/mod.rs",
    "chain/chain/src/state_sync/state_request_tracker.rs",
    "chain/chain/src/state_sync/utils.rs",
    "chain/chain/src/stateless_validation/chunk_endorsement.rs",
    "chain/chain/src/stateless_validation/chunk_validation.rs",
    "chain/chain/src/stateless_validation/processing_tracker.rs",
    "chain/chain/src/stateless_validation/state_witness.rs",
    "chain/chain/src/types.rs",
    "chain/chain/src/update_shard.rs",
    "chain/chain/src/validate.rs",
    "chain/chunks/src/chunk_cache.rs",
    "chain/chunks/src/client.rs",
    "chain/chunks/src/logic.rs",
    "chain/chunks/src/shards_manager_actor.rs",
    "chain/client/src/chunk_endorsement_handler.rs",
    "chain/client/src/chunk_inclusion_tracker.rs",
    "chain/client/src/chunk_producer.rs",
    "chain/client/src/client.rs",
    "chain/client/src/client_actor.rs",
    "chain/client/src/pending_transaction_queue.rs",
    "chain/client/src/prepare_transactions.rs",
    "chain/client/src/rpc_handler.rs",
    "chain/client/src/state_request_actor.rs",
    "chain/client/src/stateless_validation/chunk_endorsement.rs",
    "chain/client/src/stateless_validation/chunk_validation_actor.rs",
    "chain/client/src/stateless_validation/chunk_validator/mod.rs",
    "chain/client/src/stateless_validation/chunk_validator/orphan_witness_pool.rs",
    "chain/client/src/stateless_validation/partial_witness/encoding.rs",
    "chain/client/src/stateless_validation/partial_witness/partial_deploys_tracker.rs",
    "chain/client/src/stateless_validation/partial_witness/partial_witness_actor.rs",
    "chain/client/src/stateless_validation/partial_witness/partial_witness_tracker.rs",
    "chain/client/src/stateless_validation/shadow_validate.rs",
    "chain/client/src/stateless_validation/state_witness_producer.rs",
    "chain/client/src/stateless_validation/state_witness_tracker.rs",
    "chain/client/src/stateless_validation/validate.rs",
    "chain/client/src/sync/block.rs",
    "chain/client/src/sync/epoch.rs",
    "chain/client/src/sync/external.rs",
    "chain/client/src/sync/handler.rs",
    "chain/client/src/sync/header.rs",
    "chain/client/src/sync/state/chain_requests.rs",
    "chain/client/src/sync/state/downloader.rs",
    "chain/client/src/sync/state/mod.rs",
    "chain/client/src/sync/state/network.rs",
    "chain/client/src/sync/state/shard.rs",
    "chain/client/src/sync/state/task_tracker.rs",
    "chain/client/src/sync/state/util.rs",
    "chain/client/src/view_client_actor.rs",
    "chain/epoch-manager/src/epoch_info_aggregator.rs",
    "chain/epoch-manager/src/epoch_sync.rs",
    "chain/epoch-manager/src/lib.rs",
    "chain/epoch-manager/src/reward_calculator.rs",
    "chain/epoch-manager/src/shard_assignment/mod.rs",
    "chain/epoch-manager/src/shard_assignment/sticky_resharding.rs",
    "chain/epoch-manager/src/shard_tracker.rs",
    "chain/epoch-manager/src/validator_selection.rs",
    "chain/epoch-manager/src/validator_stats.rs",
    "chain/jsonrpc/src/api/blocks.rs",
    "chain/jsonrpc/src/api/call_function.rs",
    "chain/jsonrpc/src/api/chunks.rs",
    "chain/jsonrpc/src/api/light_client.rs",
    "chain/jsonrpc/src/api/query.rs",
    "chain/jsonrpc/src/api/status.rs",
    "chain/jsonrpc/src/api/transactions.rs",
    "chain/jsonrpc/src/api/validator.rs",
    "chain/jsonrpc/src/api/view_access_key.rs",
    "chain/jsonrpc/src/api/view_account.rs",
    "chain/jsonrpc/src/api/view_code.rs",
    "chain/jsonrpc/src/api/view_state.rs",
    "chain/jsonrpc/src/sharded_rpc.rs",
    "chain/network/src/accounts_data/mod.rs",
    "chain/network/src/announce_accounts/mod.rs",
    "chain/network/src/client.rs",
    "chain/network/src/network_protocol/edge.rs",
    "chain/network/src/network_protocol/mod.rs",
    "chain/network/src/network_protocol/peer.rs",
    "chain/network/src/network_protocol/state_sync.rs",
    "chain/network/src/peer/peer_actor.rs",
    "chain/network/src/peer_manager/peer_manager_actor.rs",
    "chain/network/src/routing/edge.rs",
    "chain/network/src/routing/graph/mod.rs",
    "chain/network/src/shards_manager.rs",
    "chain/network/src/state_sync.rs",
    "chain/network/src/state_witness.rs",
    "chain/network/src/types.rs",
    "chain/pool/src/lib.rs",
    "chain/pool/src/types.rs",
    "core/crypto/src/hash.rs",
    "core/crypto/src/hash_domain.rs",
    "core/crypto/src/signature.rs",
    "core/crypto/src/signer.rs",
    "core/crypto/src/vrf.rs",
    "core/primitives-core/src/account.rs",
    "core/primitives-core/src/apply.rs",
    "core/primitives-core/src/gas.rs",
    "core/primitives-core/src/hash.rs",
    "core/primitives-core/src/serialize.rs",
    "core/primitives-core/src/trie_key.rs",
    "core/primitives-core/src/types.rs",
    "core/primitives/src/action/mod.rs",
    "core/primitives/src/block.rs",
    "core/primitives/src/block_body.rs",
    "core/primitives/src/block_header.rs",
    "core/primitives/src/challenge.rs",
    "core/primitives/src/congestion_info.rs",
    "core/primitives/src/epoch_block_info.rs",
    "core/primitives/src/epoch_info.rs",
    "core/primitives/src/epoch_manager.rs",
    "core/primitives/src/epoch_sync.rs",
    "core/primitives/src/merkle.rs",
    "core/primitives/src/optimistic_block.rs",
    "core/primitives/src/receipt.rs",
    "core/primitives/src/reed_solomon.rs",
    "core/primitives/src/shard_layout/mod.rs",
    "core/primitives/src/shard_layout/v1.rs",
    "core/primitives/src/shard_layout/v2.rs",
    "core/primitives/src/shard_layout/v3.rs",
    "core/primitives/src/sharding.rs",
    "core/primitives/src/sharding/shard_chunk_header_inner.rs",
    "core/primitives/src/spice/chunk_endorsement.rs",
    "core/primitives/src/spice/partial_data.rs",
    "core/primitives/src/spice/state_witness.rs",
    "core/primitives/src/state.rs",
    "core/primitives/src/state_part.rs",
    "core/primitives/src/state_record.rs",
    "core/primitives/src/state_sync.rs",
    "core/primitives/src/stateless_validation/chunk_endorsement.rs",
    "core/primitives/src/stateless_validation/chunk_endorsements_bitmap.rs",
    "core/primitives/src/stateless_validation/contract_distribution.rs",
    "core/primitives/src/stateless_validation/partial_witness.rs",
    "core/primitives/src/stateless_validation/state_witness.rs",
    "core/primitives/src/stateless_validation/stored_chunk_state_transition_data.rs",
    "core/primitives/src/stateless_validation/validator_assignment.rs",
    "core/primitives/src/transaction.rs",
    "core/primitives/src/trie_key.rs",
    "core/primitives/src/trie_split.rs",
    "core/primitives/src/types.rs",
    "core/primitives/src/upgrade_schedule.rs",
    "core/primitives/src/validator_mandates/compute_price.rs",
    "core/primitives/src/validator_signer.rs",
    "core/store/src/adapter/chain_store.rs",
    "core/store/src/adapter/chunk_store.rs",
    "core/store/src/adapter/epoch_store.rs",
    "core/store/src/adapter/flat_store.rs",
    "core/store/src/adapter/trie_store.rs",
    "core/store/src/flat/delta.rs",
    "core/store/src/flat/manager.rs",
    "core/store/src/flat/storage.rs",
    "core/store/src/flat/types.rs",
    "core/store/src/merkle_proof.rs",
    "core/store/src/trie/from_flat.rs",
    "core/store/src/trie/iterator.rs",
    "core/store/src/trie/mem/loading.rs",
    "core/store/src/trie/mem/memtries.rs",
    "core/store/src/trie/mem/memtrie_update.rs",
    "core/store/src/trie/ops/insert_delete.rs",
    "core/store/src/trie/ops/interface.rs",
    "core/store/src/trie/ops/iter.rs",
    "core/store/src/trie/ops/resharding.rs",
    "core/store/src/trie/ops/squash.rs",
    "core/store/src/trie/raw_node.rs",
    "core/store/src/trie/receipts_column_helper.rs",
    "core/store/src/trie/shard_tries.rs",
    "core/store/src/trie/split.rs",
    "core/store/src/trie/state_parts.rs",
    "core/store/src/trie/state_snapshot.rs",
    "core/store/src/trie/trie_recording.rs",
    "core/store/src/trie/trie_storage.rs",
    "core/store/src/trie/trie_storage_update.rs",
    "core/store/src/trie/update.rs",
    "nearcore/src/config_validate.rs",
    "nearcore/src/state_sync.rs",
    "neard/src/cli.rs",
    "neard/src/main.rs",
    "runtime/near-vm-runner/src/cache.rs",
    "runtime/near-vm-runner/src/features.rs",
    "runtime/near-vm-runner/src/imports.rs",
    "runtime/near-vm-runner/src/logic/alt_bn128.rs",
    "runtime/near-vm-runner/src/logic/bls12381.rs",
    "runtime/near-vm-runner/src/logic/context.rs",
    "runtime/near-vm-runner/src/logic/gas_counter.rs",
    "runtime/near-vm-runner/src/logic/logic.rs",
    "runtime/near-vm-runner/src/logic/recorded_storage_counter.rs",
    "runtime/near-vm-runner/src/logic/vmstate.rs",
    "runtime/near-vm-runner/src/prepare.rs",
    "runtime/near-vm-runner/src/prepare/instrument_v3.rs",
    "runtime/near-vm-runner/src/prepare/prepare_v2.rs",
    "runtime/near-vm-runner/src/prepare/prepare_v3.rs",
    "runtime/near-vm-runner/src/runner.rs",
    "runtime/near-vm-runner/src/wasmtime_runner/logic.rs",
    "runtime/near-vm-runner/src/wasmtime_runner/mod.rs",
    "runtime/runtime/src/access_keys.rs",
    "runtime/runtime/src/action_validation.rs",
    "runtime/runtime/src/actions.rs",
    "runtime/runtime/src/adapter.rs",
    "runtime/runtime/src/bandwidth_scheduler/distribute_remaining.rs",
    "runtime/runtime/src/bandwidth_scheduler/scheduler.rs",
    "runtime/runtime/src/cache_warming.rs",
    "runtime/runtime/src/congestion_control.rs",
    "runtime/runtime/src/contract_code.rs",
    "runtime/runtime/src/conversions.rs",
    "runtime/runtime/src/deterministic_account_id.rs",
    "runtime/runtime/src/ext.rs",
    "runtime/runtime/src/function_call.rs",
    "runtime/runtime/src/global_contracts.rs",
    "runtime/runtime/src/pipelining.rs",
    "runtime/runtime/src/prefetch.rs",
    "runtime/runtime/src/receipt_manager.rs",
    "runtime/runtime/src/types.rs",
    "runtime/runtime/src/verifier.rs",
]

target_scopes = [
    "Critical. Unprivileged-user-triggered Receipt causality, promise dependencies, data receipts, yield/resume, timeout, or refund ordering bug executes work twice, too early, for the wrong account, or after rollback in a way that changes balances or persistent state.",
    "Critical. Unprivileged-user-triggered Account, access-key, delegate-action, gas-key, predecessor/receiver, signer, or implicit-account validation bug lets an unauthorized party spend funds, mutate account state, deploy code, or schedule receipts.",
    "Critical. Unprivileged-user-triggered Token balance, storage staking, rent-like storage accounting, validator reward, slashing, gas refund, burnt gas, or locked balance logic mints, burns, unlocks, refunds, or transfers the wrong amount.",
    "Critical. Unprivileged-user-triggered WASM preparation, instrumentation, VM feature gating, compiled-code cache, host-function dispatch, or gas metering bug executes code under the wrong protocol/runtime configuration or charges a lower cost than the canonical schedule.",
    "Critical. Unprivileged-user-triggered Trie key namespace, account subtree, contract code/data, access-key storage, delayed receipt queue, buffered receipt, or promise-yield record bug reads, writes, deletes, or rolls back state for the wrong account or shard.",
    "High. Unprivileged-user-triggered Global contract deployment/distribution, code hash resolution, contract cache warming, or contract metadata handling executes stale, wrong, or unauthorized code for a valid receipt or query path.",
    "High. Unprivileged-user-triggered View/RPC/light-client response, Merkle proof construction, block/chunk lookup, finality selection, or query routing bug returns a verified-looking but stale, wrong, or cross-shard value to clients that rely on nearcore proof semantics.",
    "High. Unprivileged-user-triggered Runtime config, protocol parameter, fee table, bandwidth/congestion limit, or feature activation boundary applies costs, limits, or validation rules from the wrong epoch/protocol version.",
    "High. Unprivileged-user-triggered Transaction pool, nonce-mode, relayer/gas-key admission, action validation, or revalidation logic lets a transaction pass pre-inclusion checks that canonical runtime validation must reject, or drops a valid transaction for protocol-invalid reasons.",
]


def question_generator(target_file: str) -> str:
    """
    Generate ledger-safety audit and fuzzing questions for one nearcore target.

    target_file format:
    "'File Name: runtime/runtime/src/actions.rs -> Scope: Critical. Unprivileged-user-triggered Token balance, storage staking, validator reward, slashing, gas refund, burnt gas, or locked balance logic mints, burns, unlocks, refunds, or transfers the wrong amount.'"
    """

    prompt = f"""
    ```

    Generate ledger-safety audit and fuzzing questions for this exact nearcore target:

    {target_file}

    Lens:
    This is `nearcore`, the Rust reference node for NEAR. This pass is not the same as a generic consensus/network review. Focus on ledger integrity, authorization, economic accounting, contract execution configuration, state namespace isolation, and client-facing proof/query trust.

    Useful project anchors:
    `Runtime::apply`, `apply_actions`, `process_transactions`, `verify_and_charge_tx_ephemeral`, `validate_receipt`, `Action`, `Receipt`, `ActionReceipt`, `DataReceipt`, `TrieUpdate`, `TrieKey`, `StateRecord`, `Account`, `AccessKey`, gas keys, delegate actions, global contracts, `near-vm-runner`, `prepare_v2/v3`, host functions, runtime config, protocol features, `ViewClientActor`, JSON-RPC query APIs, Merkle proofs, and state/view routing.

    Generate questions by triangulating:
    * Authority: who is allowed to create this transaction, action, receipt, state write, code deployment, or query proof?
    * Accounting: which balance, locked balance, storage usage, gas, refund, reward, burn, or fee value must be conserved?
    * Causality: which receipt/data dependency/yield/resume/timeout must happen exactly once and in the intended order?
    * Configuration: which protocol version, runtime config, VM feature set, fee table, or cache key must be in force?
    * Isolation: which account, shard, trie prefix, code hash, global contract, or state record is allowed to be touched?

    Required invariants:
    * Funds, storage staking, gas purchases/refunds, validator payouts, burns, and locked balances must be conserved according to runtime config.
    * Signers, predecessors, receivers, access keys, gas keys, and delegate actions must not authorize broader state changes than intended.
    * Receipts and promise data must not be duplicated, skipped, reordered across dependency barriers, or revived after rollback/timeout.
    * Contract code must be prepared, cached, selected, and executed under the exact protocol/runtime feature set for the chunk being applied.
    * View/RPC/proof outputs must not look verified while mixing wrong block height, shard, finality, code hash, or state root.

    Rules:
    * Treat `File Name:` as the exact file/module.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Attacker must be an unprivileged user: ordinary account holder, contract deployer/caller, public RPC client, or unauthenticated/low-trust peer using public inputs.
    * Unprivileged attacker may control validly signed transactions for their own keys/accounts, action fields they can submit, contract code/input they can deploy or call, gas-key/delegate-action parameters they can create, account names, attached deposits, access-key permissions they are allowed to set, receipt graphs created by their contracts, and RPC query parameters.
    * Do not grant validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges unless the bug lets an unprivileged user bypass that authority boundary.
    * Malicious-peer-only behavior is out of scope unless nearcore turns bad peer data into an accepted ledger/proof/accounting result.
    * Do not rely on admin/operator mistakes, unsafe config/genesis/DB edits, debug/adversarial flags, compromised validators, privileged relayers, social engineering, dependency-only bugs, or downstream misuse outside nearcore APIs.
    * Exclude ordinary crash/DoS, unbounded resource growth, memory leaks/OOM, logging/UI/docs/tests/mocks/benches/tooling, and Rust memory-management hygiene unless a scoped ledger/proof result changes.
    * Generate 16 to 24 high-signal questions.
    * At least two thirds should cross function/module boundaries.
    * Each question must be testable with `cargo test --package ... --features test_features`, a property/fuzz test, a runtime state test, a test-loop test, or a focused local reproducer.
    * Avoid repeating the same authorization/accounting/cache root cause.
    * Anchor questions to concrete structs, fields, methods, protocol feature flags, trie keys, receipts, actions, accounts, config values, cache keys, or RPC methods.
    * Name the exact value at risk: account balance, locked balance, storage usage, nonce, allowance, gas/refund/burn, receipt id, data id, promise result, code hash, state key/value, proof root, query result, or VM gas counter.

    Do not ask broad questions about block/header/finality validation, state witness forgery, network routing, or sync recovery unless the target file connects them to one of the target scopes above.

    Each question must include:
    1. target symbol;
    2. attacker-controlled field/input;
    3. required protocol/account state;
    4. call path;
    5. ledger/proof invariant;
    6. exact corrupted value;
    7. scoped impact and proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Symbol: symbol_or_module] Can attacker-controlled FIELD under STATE force CALL_PATH to violate LEDGER_OR_PROOF_INVARIANT, corrupting EXACT_VALUE with scoped impact SCOPE_IMPACT? Proof idea: build a Rust runtime/property/test-loop reproducer over PARAMETERS and assert EXPECTED_CONSERVATION_OR_AUTHORIZATION_PROPERTY.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused nearcore ledger-safety question validation prompt.
    """
    return f"""# LEDGER-SAFETY QUESTION REVIEW

## Exploit Question
{question}

## Boundary
- Audit only production nearcore repository code listed in `scope_files`.
- Do not ask for repo contents or claim files are missing.
- Ignore tests, docs, mocks, test utilities, fuzz harnesses, benches, generated data, automation, packaging, scripts, and local-only tools.

## Goal
Determine whether the question can lead to a real nearcore issue in the target scope. The path must start from an unprivileged user's supported production inputs such as transactions signed by their own keys, receipts produced by their contracts, action parameters they can submit, access-key/gas-key/delegate-action data they can create, contract code/input they can deploy or call, or public RPC/view query parameters.

Do not assume validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges unless the question is specifically about an unprivileged bypass of that boundary.

The issue must break a ledger, authorization, execution-configuration, state-namespace, or client-proof invariant. Prefer #NoVulnerability unless the exact corrupted value and production call path are both concrete.

## Review Steps
1. Identify the exact target symbol and reachable caller.
2. Trace attacker-controlled fields into account/action/receipt/runtime/view state.
3. Check authorization, nonce, allowance, attached deposit, storage staking, gas purchase/refund, receipt dependency, rollback, protocol feature, VM cache key, trie key, and proof-root guards as applicable.
4. Name the exact balance, nonce, storage usage, receipt/data id, code hash, state key, gas counter, proof root, or query result that would be wrong.
5. Reject if the current code always errors, rolls back, burns/refunds correctly, selects the right config, or returns an unverifiable/non-authoritative value.
6. Require file/function references and a realistic test plan.

## Fast Rejections
- Admin/operator error, unsafe config/genesis/DB edits, bad key custody, debug/adversarial mode, non-production flags, or local deployment mistakes.
- Requires validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges not obtainable by an unprivileged user.
- Malicious-peer-only behavior where bad data is rejected, ignored, retried, rate-limited, disconnected, or only consumes resources.
- Ordinary crash, DoS, timeout, memory growth, queue growth, cache retention, leak, OOM, logging/display issue, harmless rejection, style, or best practice.
- Dependency-only behavior or downstream misuse outside nearcore's production API contract.
- No exact corrupted ledger/proof value, or no path from supported attacker-controlled input.
- Broader block/finality/sync/network claims that do not match this file and the selected target scope.

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
    Generate a short cross-project analog scan prompt for nearcore ledger-safety issues.
    """
    prompt = f"""# LEDGER ANALOG SCAN

## External Report
{report}

## Task
Use the external report only as a bug-class seed. Search for a nearcore-native analog in production files from `scope_files`, but only in the target scopes for this file: accounting, authorization, receipt causality, VM/config selection, trie namespace isolation, global contract/code selection, RPC proof/query trust, or pre-inclusion transaction validation.

Do not claim missing files. Do not audit tests, docs, mocks, benches, fuzz harnesses, generated data, scripts, packaging, or local tooling.

## Analog Standard
Report only if nearcore has its own reachable root cause, unprivileged-user-controlled production input, broken invariant, exact corrupted value, and scoped High/Critical impact. Similar words or a generic bug pattern are insufficient.

Reject analogs based on:
- admin/operator mistakes, unsafe manual config/genesis/DB edits, wrong key custody, debug/adversarial modes, or deployment choices;
- validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges not obtainable by an unprivileged user;
- malicious-peer noise where bad data is rejected/ignored/retried/rate-limited or only wastes resources;
- ordinary crash, DoS, memory/cache/queue growth, OOM, leak, logging, style, or best-practice cleanup;
- dependency-only behavior or downstream misuse outside nearcore APIs.

## Work Plan
1. Translate the external bug into one nearcore invariant: authorization, conservation, causality, configuration, namespace, code identity, proof identity, or transaction admission.
2. Map that invariant to exact production symbols.
3. Trace attacker-controlled fields through the call path.
4. Identify the exact corrupted balance, nonce, storage usage, gas/refund, receipt id, code hash, state key/value, proof root, query result, or admission decision.
5. Check existing guards and explain why they fail.
6. Reject if the target scope is not matched exactly.

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
    Generate a strict nearcore ledger-safety validation prompt for security claims.
    """
    prompt = f"""# LEDGER-SAFETY VALIDATION

## Security Claim
{report}

## Validation Rules
- Validate only this claim against production nearcore files in `scope_files`.
- Do not invent a stronger claim or switch to a different target scope.
- A valid issue must be reachable through an unprivileged user's supported production inputs: transactions signed by their own keys, action fields they can submit, contract code/input they can deploy or call, receipt graphs produced by their contracts, access-key/gas-key/delegate-action parameters they can create, account IDs, attached deposits, or public RPC/view query parameters.
- The final impact must match one of the allowed scopes below and must name the exact corrupted ledger/proof/admission value.
- Reject speculative bug classes, best practices, and reports that never move from "could be confusing" to a concrete incorrect value.
- Reject admin/operator mistakes, unsafe manual DB/config/genesis edits, bad key custody, non-production flags, debug/adversarial modes, dependency-only bugs, downstream misuse, and environment-specific setup.
- Reject claims requiring validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges unless the report proves an unprivileged user can bypass that boundary.
- Reject malicious-peer-only claims where bad peer data is rejected, ignored, retried, disconnected, rate-limited, or only wastes resources.
- Reject ordinary crash/DoS, unbounded CPU/memory/disk/cache/queue growth, leaks, OOM, allocation pressure, logging/display issues, and Rust memory-management hygiene unless they deterministically corrupt a scoped ledger/proof/admission value.

## Allowed Impact Scope
Only these impacts are valid:
- Critical. Unprivileged-user-triggered Receipt causality, promise dependencies, data receipts, yield/resume, timeout, or refund ordering bug executes work twice, too early, for the wrong account, or after rollback in a way that changes balances or persistent state.
- Critical. Unprivileged-user-triggered Account, access-key, delegate-action, gas-key, predecessor/receiver, signer, or implicit-account validation bug lets an unauthorized party spend funds, mutate account state, deploy code, or schedule receipts.
- Critical. Unprivileged-user-triggered Token balance, storage staking, rent-like storage accounting, validator reward, slashing, gas refund, burnt gas, or locked balance logic mints, burns, unlocks, refunds, or transfers the wrong amount.
- Critical. Unprivileged-user-triggered WASM preparation, instrumentation, VM feature gating, compiled-code cache, host-function dispatch, or gas metering bug executes code under the wrong protocol/runtime configuration or charges a lower cost than the canonical schedule.
- Critical. Unprivileged-user-triggered Trie key namespace, account subtree, contract code/data, access-key storage, delayed receipt queue, buffered receipt, or promise-yield record bug reads, writes, deletes, or rolls back state for the wrong account or shard.
- High. Unprivileged-user-triggered Global contract deployment/distribution, code hash resolution, contract cache warming, or contract metadata handling executes stale, wrong, or unauthorized code for a valid receipt or query path.
- High. Unprivileged-user-triggered View/RPC/light-client response, Merkle proof construction, block/chunk lookup, finality selection, or query routing bug returns a verified-looking but stale, wrong, or cross-shard value to clients that rely on nearcore proof semantics.
- High. Unprivileged-user-triggered Runtime config, protocol parameter, fee table, bandwidth/congestion limit, or feature activation boundary applies costs, limits, or validation rules from the wrong epoch/protocol version.
- High. Unprivileged-user-triggered Transaction pool, nonce-mode, relayer/gas-key admission, action validation, or revalidation logic lets a transaction pass pre-inclusion checks that canonical runtime validation must reject, or drops a valid transaction for protocol-invalid reasons.

If the submitted claim does not concretely prove one of the allowed impacts above, it is invalid.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function, and line or code references.
2. Clear root cause and broken authorization, accounting, causality, VM/config, namespace, code-identity, proof-identity, or transaction-admission invariant.
3. Reachable exploit path: preconditions -> attacker-controlled field -> production call path -> bad value.
4. Existing validation, rollback, charging, permission, feature, cache-key, trie-key, and proof checks reviewed and shown insufficient.
5. Exact corrupted value identified: account balance, locked balance, storage usage, nonce, allowance, gas/refund/burn, reward/slash amount, receipt id, data id, promise result, code hash, trie key/value, proof root, query result, or admission decision.
6. Concrete impact that exactly matches one allowed scope above, with realistic likelihood.
7. Reproducible proof path: Rust unit/property test, runtime state test, VM test, test-loop test, or focused local reproducer.
8. No rejection reason from privileged-role requirements, admin/operator error, malicious-peer-only behavior, resource-only behavior, dependency-only behavior, or scope exclusions.

## Silent Triage Questions
Before output, internally answer:
- Which supported attacker-controlled field triggers this?
- Can an unprivileged user trigger this without validator, block producer, chunk producer, relayer operator, node admin, wallet custodian, or trusted-service privileges?
- Which account, receipt, contract, trie key, proof, config, or transaction-admission value becomes wrong?
- Does an existing validation, rollback, gas charge, permission check, cache key, or proof check already prevent it?
- Does the code actually behave as claimed?
- Is the impact caused by this repository, not by an external dependency alone?
- Is this more than admin error, malicious-peer noise, resource exhaustion, or memory-management cleanup?
- What conservation, authorization, causality, configuration, namespace, code identity, proof identity, or transaction-admission rule is broken?
- Would a security triager accept the proof?
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
[Concrete allowed repository impact and severity rationale]

## Likelihood Explanation
[Attacker capability, required conditions, feasibility, repeatability]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or fuzz, differential, property, or state test plan]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt
