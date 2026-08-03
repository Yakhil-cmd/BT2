import json
import os

MAX_REPO = 40
SOURCE_REPO = 'paritytech/polkadot-sdk'
REPO_NAME = 'polkadot-sdk'
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
    'substrate/frame/assets/src/extra_mutator.rs',
    'substrate/frame/assets/src/functions.rs',
    'substrate/frame/assets/src/impl_fungibles.rs',
    'substrate/frame/assets/src/impl_stored_map.rs',
    'substrate/frame/assets/src/lib.rs',
    'substrate/frame/assets/src/types.rs',
    'substrate/frame/asset-conversion/src/lib.rs',
    'substrate/frame/asset-conversion/src/liquidity.rs',
    'substrate/frame/asset-conversion/src/swap.rs',
    'substrate/frame/asset-conversion/src/types.rs',
    'substrate/frame/asset-rewards/src/lib.rs',
    'substrate/frame/atomic-swap/src/lib.rs',
    'substrate/frame/balances/src/impl_currency.rs',
    'substrate/frame/balances/src/impl_fungible.rs',
    'substrate/frame/balances/src/lib.rs',
    'substrate/frame/balances/src/types.rs',
    'substrate/frame/bounties/src/lib.rs',
    'substrate/frame/contracts/src/address.rs',
    'substrate/frame/contracts/src/chain_extension.rs',
    'substrate/frame/contracts/src/debug.rs',
    'substrate/frame/contracts/src/exec.rs',
    'substrate/frame/contracts/src/gas.rs',
    'substrate/frame/contracts/src/lib.rs',
    'substrate/frame/contracts/src/primitives.rs',
    'substrate/frame/contracts/src/schedule.rs',
    'substrate/frame/contracts/src/storage/meter.rs',
    'substrate/frame/contracts/src/storage.rs',
    'substrate/frame/contracts/src/transient_storage.rs',
    'substrate/frame/contracts/src/wasm/mod.rs',
    'substrate/frame/contracts/src/wasm/prepare.rs',
    'substrate/frame/contracts/src/wasm/runtime.rs',
    'substrate/frame/conviction-voting/src/conviction.rs',
    'substrate/frame/conviction-voting/src/lib.rs',
    'substrate/frame/conviction-voting/src/traits.rs',
    'substrate/frame/conviction-voting/src/types.rs',
    'substrate/frame/conviction-voting/src/vote.rs',
    'substrate/frame/democracy/src/conviction.rs',
    'substrate/frame/democracy/src/lib.rs',
    'substrate/frame/democracy/src/types.rs',
    'substrate/frame/democracy/src/vote.rs',
    'substrate/frame/democracy/src/vote_threshold.rs',
    'substrate/frame/fast-unstake/src/lib.rs',
    'substrate/frame/fast-unstake/src/types.rs',
    'substrate/frame/identity/src/legacy.rs',
    'substrate/frame/identity/src/lib.rs',
    'substrate/frame/identity/src/types.rs',
    'substrate/frame/indices/src/lib.rs',
    'substrate/frame/lottery/src/lib.rs',
    'substrate/frame/message-queue/src/lib.rs',
    'substrate/frame/meta-tx/src/extension.rs',
    'substrate/frame/meta-tx/src/lib.rs',
    'substrate/frame/multisig/src/lib.rs',
    'substrate/frame/nft-fractionalization/src/lib.rs',
    'substrate/frame/nft-fractionalization/src/types.rs',
    'substrate/frame/nfts/src/common_functions.rs',
    'substrate/frame/nfts/src/features/approvals.rs',
    'substrate/frame/nfts/src/features/atomic_swap.rs',
    'substrate/frame/nfts/src/features/attributes.rs',
    'substrate/frame/nfts/src/features/buy_sell.rs',
    'substrate/frame/nfts/src/features/create_delete_collection.rs',
    'substrate/frame/nfts/src/features/create_delete_item.rs',
    'substrate/frame/nfts/src/features/lock.rs',
    'substrate/frame/nfts/src/features/metadata.rs',
    'substrate/frame/nfts/src/features/mod.rs',
    'substrate/frame/nfts/src/features/roles.rs',
    'substrate/frame/nfts/src/features/settings.rs',
    'substrate/frame/nfts/src/features/transfer.rs',
    'substrate/frame/nfts/src/impl_nonfungibles.rs',
    'substrate/frame/nfts/src/lib.rs',
    'substrate/frame/nfts/src/macros.rs',
    'substrate/frame/nfts/src/types.rs',
    'substrate/frame/nomination-pools/src/adapter.rs',
    'substrate/frame/nomination-pools/src/lib.rs',
    'substrate/frame/preimage/src/lib.rs',
    'substrate/frame/proxy/src/lib.rs',
    'substrate/frame/psm/src/lib.rs',
    'substrate/frame/recovery/src/lib.rs',
    'substrate/frame/recovery/src/types.rs',
    'substrate/frame/referenda/src/branch.rs',
    'substrate/frame/referenda/src/lib.rs',
    'substrate/frame/referenda/src/types.rs',
    'substrate/frame/revive/src/access_list.rs',
    'substrate/frame/revive/src/address.rs',
    'substrate/frame/revive/src/call_builder.rs',
    'substrate/frame/revive/src/debug.rs',
    'substrate/frame/revive/src/deposit_payment.rs',
    'substrate/frame/revive/src/evm/api/account.rs',
    'substrate/frame/revive/src/evm/api/block.rs',
    'substrate/frame/revive/src/evm/api/debug_rpc_types.rs',
    'substrate/frame/revive/src/evm/api/rlp_codec.rs',
    'substrate/frame/revive/src/evm/api/signature.rs',
    'substrate/frame/revive/src/evm/api/state_overrides.rs',
    'substrate/frame/revive/src/evm/api/transaction.rs',
    'substrate/frame/revive/src/evm/api.rs',
    'substrate/frame/revive/src/evm/block_hash/block_builder.rs',
    'substrate/frame/revive/src/evm/block_hash/hash_builder.rs',
    'substrate/frame/revive/src/evm/block_hash/receipt.rs',
    'substrate/frame/revive/src/evm/block_hash.rs',
    'substrate/frame/revive/src/evm/block_storage.rs',
    'substrate/frame/revive/src/evm/call.rs',
    'substrate/frame/revive/src/evm/fees.rs',
    'substrate/frame/revive/src/evm/runtime.rs',
    'substrate/frame/revive/src/evm/tracing/call_tracing.rs',
    'substrate/frame/revive/src/evm/tracing/execution_tracing.rs',
    'substrate/frame/revive/src/evm/tracing/prestate_tracing.rs',
    'substrate/frame/revive/src/evm/tracing.rs',
    'substrate/frame/revive/src/evm/transfer_with_dust.rs',
    'substrate/frame/revive/src/evm/tx_extension.rs',
    'substrate/frame/revive/src/evm.rs',
    'substrate/frame/revive/src/exec.rs',
    'substrate/frame/revive/src/impl_fungibles.rs',
    'substrate/frame/revive/src/lib.rs',
    'substrate/frame/revive/src/limits.rs',
    'substrate/frame/revive/src/metering/gas.rs',
    'substrate/frame/revive/src/metering/math.rs',
    'substrate/frame/revive/src/metering/mod.rs',
    'substrate/frame/revive/src/metering/storage.rs',
    'substrate/frame/revive/src/metering/weight.rs',
    'substrate/frame/revive/src/precompiles/builtin/blake2f.rs',
    'substrate/frame/revive/src/precompiles/builtin/bn128.rs',
    'substrate/frame/revive/src/precompiles/builtin/ecrecover.rs',
    'substrate/frame/revive/src/precompiles/builtin/identity.rs',
    'substrate/frame/revive/src/precompiles/builtin/modexp.rs',
    'substrate/frame/revive/src/precompiles/builtin/p256_verify.rs',
    'substrate/frame/revive/src/precompiles/builtin/point_eval.rs',
    'substrate/frame/revive/src/precompiles/builtin/ripemd160.rs',
    'substrate/frame/revive/src/precompiles/builtin/sha256.rs',
    'substrate/frame/revive/src/precompiles/builtin/storage.rs',
    'substrate/frame/revive/src/precompiles/builtin/system.rs',
    'substrate/frame/revive/src/precompiles/builtin.rs',
    'substrate/frame/revive/src/precompiles.rs',
    'substrate/frame/revive/src/primitives.rs',
    'substrate/frame/revive/src/runtime_api/account_id.rs',
    'substrate/frame/revive/src/runtime_api/address.rs',
    'substrate/frame/revive/src/runtime_api/balance.rs',
    'substrate/frame/revive/src/runtime_api/block_author.rs',
    'substrate/frame/revive/src/runtime_api/block_gas_limit.rs',
    'substrate/frame/revive/src/runtime_api/block_hash.rs',
    'substrate/frame/revive/src/runtime_api/call.rs',
    'substrate/frame/revive/src/runtime_api/code.rs',
    'substrate/frame/revive/src/runtime_api/eth_block.rs',
    'substrate/frame/revive/src/runtime_api/eth_estimate_gas.rs',
    'substrate/frame/revive/src/runtime_api/eth_pre_dispatch_weight.rs',
    'substrate/frame/revive/src/runtime_api/eth_transact.rs',
    'substrate/frame/revive/src/runtime_api/gas_price.rs',
    'substrate/frame/revive/src/runtime_api/get_storage.rs',
    'substrate/frame/revive/src/runtime_api/instantiate.rs',
    'substrate/frame/revive/src/runtime_api/max_extrinsic_weight_in_gas.rs',
    'substrate/frame/revive/src/runtime_api/mod.rs',
    'substrate/frame/revive/src/runtime_api/new_balance_with_dust.rs',
    'substrate/frame/revive/src/runtime_api/nonce.rs',
    'substrate/frame/revive/src/runtime_api/receipt_data.rs',
    'substrate/frame/revive/src/runtime_api/runtime_pallets_address.rs',
    'substrate/frame/revive/src/runtime_api/trace_block.rs',
    'substrate/frame/revive/src/runtime_api/trace_call.rs',
    'substrate/frame/revive/src/runtime_api/trace_tx.rs',
    'substrate/frame/revive/src/runtime_api/upload_code.rs',
    'substrate/frame/revive/src/state_overrides.rs',
    'substrate/frame/revive/src/storage.rs',
    'substrate/frame/revive/src/tracing.rs',
    'substrate/frame/revive/src/transient_storage.rs',
    'substrate/frame/revive/src/vm/evm/ext_bytecode.rs',
    'substrate/frame/revive/src/vm/evm/instructions/arithmetic/i256.rs',
    'substrate/frame/revive/src/vm/evm/instructions/arithmetic/modular.rs',
    'substrate/frame/revive/src/vm/evm/instructions/arithmetic.rs',
    'substrate/frame/revive/src/vm/evm/instructions/bitwise/bits.rs',
    'substrate/frame/revive/src/vm/evm/instructions/bitwise.rs',
    'substrate/frame/revive/src/vm/evm/instructions/block_info.rs',
    'substrate/frame/revive/src/vm/evm/instructions/contract/call_helpers.rs',
    'substrate/frame/revive/src/vm/evm/instructions/contract.rs',
    'substrate/frame/revive/src/vm/evm/instructions/control.rs',
    'substrate/frame/revive/src/vm/evm/instructions/host.rs',
    'substrate/frame/revive/src/vm/evm/instructions/memory.rs',
    'substrate/frame/revive/src/vm/evm/instructions/mod.rs',
    'substrate/frame/revive/src/vm/evm/instructions/stack.rs',
    'substrate/frame/revive/src/vm/evm/instructions/system.rs',
    'substrate/frame/revive/src/vm/evm/instructions/tx_info.rs',
    'substrate/frame/revive/src/vm/evm/instructions/utility.rs',
    'substrate/frame/revive/src/vm/evm/interpreter.rs',
    'substrate/frame/revive/src/vm/evm/memory.rs',
    'substrate/frame/revive/src/vm/evm/stack.rs',
    'substrate/frame/revive/src/vm/evm/util.rs',
    'substrate/frame/revive/src/vm/evm.rs',
    'substrate/frame/revive/src/vm/mod.rs',
    'substrate/frame/revive/src/vm/pvm/env.rs',
    'substrate/frame/revive/src/vm/pvm.rs',
    'substrate/frame/revive/src/vm/runtime_costs.rs',
    'substrate/frame/revive/src/weightinfo_extension.rs',
    'substrate/frame/scarcity/src/extension.rs',
    'substrate/frame/scarcity/src/lib.rs',
    'substrate/frame/staking/src/asset.rs',
    'substrate/frame/staking/src/election_size_tracker.rs',
    'substrate/frame/staking/src/inflation.rs',
    'substrate/frame/staking/src/ledger.rs',
    'substrate/frame/staking/src/lib.rs',
    'substrate/frame/staking/src/pallet/impls.rs',
    'substrate/frame/staking/src/pallet/mod.rs',
    'substrate/frame/staking/src/slashing.rs',
    'substrate/frame/tips/src/lib.rs',
    'substrate/frame/treasury/src/lib.rs',
    'substrate/frame/uniques/src/asset_ops/collection.rs',
    'substrate/frame/uniques/src/asset_ops/item.rs',
    'substrate/frame/uniques/src/asset_ops/mod.rs',
    'substrate/frame/uniques/src/functions.rs',
    'substrate/frame/uniques/src/impl_nonfungibles.rs',
    'substrate/frame/uniques/src/lib.rs',
    'substrate/frame/uniques/src/types.rs',
    'substrate/frame/utility/src/lib.rs',
    'substrate/frame/vesting/src/lib.rs',
    'substrate/frame/vesting/src/vesting_info.rs',
    'bridges/modules/beefy/src/lib.rs',
    'bridges/modules/beefy/src/utils.rs',
    'bridges/modules/grandpa/src/call_ext.rs',
    'bridges/modules/grandpa/src/lib.rs',
    'bridges/modules/grandpa/src/storage_types.rs',
    'bridges/modules/grandpa/src/weights_ext.rs',
    'bridges/modules/messages/src/call_ext.rs',
    'bridges/modules/messages/src/inbound_lane.rs',
    'bridges/modules/messages/src/lanes_manager.rs',
    'bridges/modules/messages/src/lib.rs',
    'bridges/modules/messages/src/outbound_lane.rs',
    'bridges/modules/messages/src/proofs.rs',
    'bridges/modules/messages/src/weights_ext.rs',
    'bridges/modules/parachains/src/call_ext.rs',
    'bridges/modules/parachains/src/lib.rs',
    'bridges/modules/parachains/src/proofs.rs',
    'bridges/modules/parachains/src/weights_ext.rs',
    'bridges/modules/relayers/src/extension/grandpa_adapter.rs',
    'bridges/modules/relayers/src/extension/messages_adapter.rs',
    'bridges/modules/relayers/src/extension/mod.rs',
    'bridges/modules/relayers/src/extension/parachain_adapter.rs',
    'bridges/modules/relayers/src/extension/priority.rs',
    'bridges/modules/relayers/src/lib.rs',
    'bridges/modules/relayers/src/payment_adapter.rs',
    'bridges/modules/relayers/src/stake_adapter.rs',
    'bridges/modules/relayers/src/weights_ext.rs',
    'bridges/primitives/header-chain/src/call_info.rs',
    'bridges/primitives/header-chain/src/justification/mod.rs',
    'bridges/primitives/header-chain/src/justification/verification/equivocation.rs',
    'bridges/primitives/header-chain/src/justification/verification/mod.rs',
    'bridges/primitives/header-chain/src/justification/verification/optimizer.rs',
    'bridges/primitives/header-chain/src/justification/verification/strict.rs',
    'bridges/primitives/header-chain/src/lib.rs',
    'bridges/primitives/header-chain/src/storage_keys.rs',
    'bridges/primitives/messages/src/call_info.rs',
    'bridges/primitives/messages/src/lane.rs',
    'bridges/primitives/messages/src/lib.rs',
    'bridges/primitives/messages/src/source_chain.rs',
    'bridges/primitives/messages/src/storage_keys.rs',
    'bridges/primitives/messages/src/target_chain.rs',
    'bridges/primitives/parachains/src/call_info.rs',
    'bridges/primitives/parachains/src/lib.rs',
    'bridges/primitives/relayers/src/extension.rs',
    'bridges/primitives/relayers/src/lib.rs',
    'bridges/primitives/relayers/src/registration.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/config/altair.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/config/electra.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/config/mod.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/functions.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/impls.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/lib.rs',
    'bridges/snowbridge/pallets/ethereum-client/src/types.rs',
    'bridges/snowbridge/pallets/inbound-queue/src/envelope.rs',
    'bridges/snowbridge/pallets/inbound-queue/src/lib.rs',
    'bridges/snowbridge/pallets/inbound-queue-v2/src/lib.rs',
    'bridges/snowbridge/pallets/outbound-queue/src/api.rs',
    'bridges/snowbridge/pallets/outbound-queue/src/lib.rs',
    'bridges/snowbridge/pallets/outbound-queue/src/process_message_impl.rs',
    'bridges/snowbridge/pallets/outbound-queue/src/send_message_impl.rs',
    'bridges/snowbridge/pallets/outbound-queue/src/types.rs',
    'bridges/snowbridge/pallets/outbound-queue-v2/src/api.rs',
    'bridges/snowbridge/pallets/outbound-queue-v2/src/lib.rs',
    'bridges/snowbridge/pallets/outbound-queue-v2/src/process_message_impl.rs',
    'bridges/snowbridge/pallets/outbound-queue-v2/src/send_message_impl.rs',
    'bridges/snowbridge/pallets/outbound-queue-v2/src/types.rs',
    'bridges/snowbridge/pallets/system/src/api.rs',
    'bridges/snowbridge/pallets/system/src/lib.rs',
    'bridges/snowbridge/pallets/system-v2/src/api.rs',
    'bridges/snowbridge/pallets/system-v2/src/lib.rs',
    'bridges/snowbridge/pallets/system-frontend/src/backend_weights.rs',
    'bridges/snowbridge/pallets/system-frontend/src/lib.rs',
    'bridges/snowbridge/primitives/beacon/src/bits.rs',
    'bridges/snowbridge/primitives/beacon/src/bls.rs',
    'bridges/snowbridge/primitives/beacon/src/config.rs',
    'bridges/snowbridge/primitives/beacon/src/lib.rs',
    'bridges/snowbridge/primitives/beacon/src/merkle_proof.rs',
    'bridges/snowbridge/primitives/beacon/src/serde_utils.rs',
    'bridges/snowbridge/primitives/beacon/src/ssz.rs',
    'bridges/snowbridge/primitives/beacon/src/types.rs',
    'bridges/snowbridge/primitives/beacon/src/updates.rs',
    'bridges/snowbridge/primitives/core/src/digest_item.rs',
    'bridges/snowbridge/primitives/core/src/lib.rs',
    'bridges/snowbridge/primitives/core/src/location.rs',
    'bridges/snowbridge/primitives/core/src/operating_mode.rs',
    'bridges/snowbridge/primitives/core/src/pricing.rs',
    'bridges/snowbridge/primitives/core/src/reward.rs',
    'bridges/snowbridge/primitives/core/src/ringbuffer.rs',
    'bridges/snowbridge/primitives/core/src/sparse_bitmap.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/lib.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v1.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v2/converter.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v2/message.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v2/mod.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v2/processor.rs',
    'bridges/snowbridge/primitives/inbound-queue/src/v2/traits.rs',
    'bridges/snowbridge/primitives/merkle-tree/src/lib.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/lib.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v1/converter/mod.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v1/message.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v1/mod.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/converter/convert.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/converter/mod.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/delivery_receipt.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/exporter.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/message.rs',
    'bridges/snowbridge/primitives/outbound-queue/src/v2/mod.rs',
    'bridges/snowbridge/primitives/verification/src/lib.rs',
    'bridges/snowbridge/primitives/verification/src/receipt.rs',
    'bridges/snowbridge/runtime/runtime-common/src/lib.rs',
    'bridges/snowbridge/runtime/runtime-common/src/v2/mod.rs',
    'bridges/snowbridge/runtime/runtime-common/src/v2/register_token.rs',
]

target_scopes = [
    'Critical. An unprivileged attacker can make Polkadot SDK or Snowbridge accept a forged, stale, conflicting, or mis-bound finality proof, parachain head, beacon update, message proof, delivery receipt, or state root and then execute or import invalid state.',
    'Critical. An unprivileged attacker can reach unauthorized execution, origin widening, or call-filter bypass through a public extrinsic, wrapper, contract path, meta-transaction, or bridge message and cause stronger-than-user effects.',
    'Critical. An unprivileged attacker can steal, mint, unlock, withdraw, claim, redirect, or duplicate native assets, fungible assets, NFTs, staking balances, pool funds, treasury payouts, bridge rewards, or contract-held value they do not own.',
    'Critical. An unprivileged attacker can replay or double-settle a message, proof, receipt, payout, withdrawal, refund, claim, unlock, approval, or contract side effect so one logical action executes or pays out more than once.',
    'High. An unprivileged attacker can permanently lock user funds, NFTs, staking balances, pool balances, bridge lanes, message queues, or contract state by breaking finalization, cleanup, custody, or one-time settlement accounting in a production flow.',
    'High. An unprivileged attacker can use a public path to trigger underpriced proof verification, VM execution, queue maintenance, or storage-heavy iteration that meaningfully degrades block production, stalls bridge progress, or keeps the chain processing attacker work below true cost.',
]

HYPERBRIDGE_ALLOWED_IMPACT_SCOPE = """## Polkadot SDK Impact Gate
Accept only live-scope impacts aligned to the current HackenProof programs for `paritytech/polkadot-sdk`
and Snowbridge BridgeHub code: implementation bugs that can bring down or take control of a Substrate-based
chain without direct machine access, runtime bugs that compromise intended behavior, forged or mis-bound
proof or state acceptance, unauthorized execution or origin escalation, theft or unbacked mint or unlock,
duplicate settlement or payout, permanent user-fund or bridge-state lock, or public underpriced work that
degrades block production or stalls bridge processing.
Discard: malicious peer, malicious node, malicious validator, malicious collator, compromised relayer or
prover assumptions, privileged governance or admin abuse as the root cause, leaked keys, social or physical
attacks, dependency-only issues, docs, tests, mocks, scripts, generated files, `.toml`, disabled configs,
front-run-only ideas, and off-repo infrastructure issues."""

HYPERBRIDGE_AUDIT_PIVOTS = """## Polkadot SDK Pivots
- Finality, header, parachain, beacon, message, and delivery-receipt proofs must bind chain, route, lane,
  authority set, nonce, payload, and replay domain exactly once.
- Public wrappers such as `utility`, `proxy`, `multisig`, `meta-tx`, `contracts`, and `revive` must not
  widen origin, bypass filters, or undercharge nested execution.
- Balances, assets, NFTs, staking, pools, treasury spends, bridge rewards, and contract-held value must
  conserve value and settle exactly once to the rightful beneficiary and amount.
- Message queues, bridge markers, receipts, and payout state must only advance after decode, dispatch,
  execution, and settlement succeed atomically."""


def question_generator(target_file: str) -> str:
    """
    Generate security questions for one Polkadot SDK target.
    """

    prompt = f"""
    Draft 18 to 24 exploit questions for this exact Polkadot SDK file:
    {target_file}

    Focus:
    Stay on proof acceptance, message routing, queue progression, public dispatch wrappers,
    contracts or revive execution, asset or NFT or staking or pool accounting, payout or claim
    or refund flows, and origin or weight or accounting failures that a normal user can trigger.

    {HYPERBRIDGE_ALLOWED_IMPACT_SCOPE}

    {HYPERBRIDGE_AUDIT_PIVOTS}

    Rules:
    * `File Name:` must be this file. `Scope:` must select exactly one `target_scopes` item.
    * Use the repository context already in hand. Do not request more code.
    * The attacker is strictly unprivileged: a normal external user using signed extrinsics,
      public proof or message submission, contract calls, runtime APIs, or user-controlled payloads.
    * Do not assume admin, governance, root, validator, collator, peer chain, node, trusted relayer,
      trusted prover, leaked keys, or off-repo infra control.
    * Never model a malicious peer, malicious node, or malicious relayer as the root cause.
    * Ignore tests, mocks, fixtures, benches, docs, readmes, generated files, `.toml`, disabled configs,
      dependency-only issues, and front-run-only ideas.
    * Prefer critical paths first, but include strong high-severity questions when justified.
    * Name the exact corrupted value: finalized header, state root, authority set, lane nonce, receipt marker,
      beneficiary, amount, balance, share supply, approval, queue marker, code refcount, or effective origin.
    * Every question must be testable with a focused Rust unit, integration, property, or fuzz-style test.

    Each question must include target symbol, attacker input, required state, execution or verification path,
    broken invariant, corrupted value, scoped impact, and proof idea.

    Return Python only.

    questions = [
    "[File Name: {target_file}] [Scope: one_target_scopes_item] [Symbol: symbol_or_type] Can attacker-controlled INPUT under REQUIRED_STATE pass VERIFY_OR_EXECUTE_PATH and break INVARIANT, corrupting EXACT_VALUE with impact SCOPE_IMPACT? Proof idea: write a focused repo test that drives the public entrypoint and asserts authenticity, one-time settlement, beneficiary, origin, or accounting correctness.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Polkadot SDK exploit-question validation prompt.
    """
    return f"""# POLKADOT SDK REVIEW

## Submitted Question
{question}

## Scope Limits
- Review only production Polkadot SDK and Snowbridge bridge, runtime, pallet, contract, and support-crate logic in this repository.
- The attacker must enter through unprivileged public extrinsics, proof or message submission, runtime APIs, callbacks, contract calls, or settlement inputs.
- Ignore malicious peers, malicious nodes, compromised relayers or provers, front-run-only claims, and excluded bounty families.

## Decision Standard
Treat it as valid only if unprivileged input can cause false proof or state acceptance, unauthorized execution, origin widening, wrongful asset movement,
duplicate settlement, wrong beneficiary or amount, permanent production fund lock, or public underpriced work that degrades block production or bridge progress.
Reject claims that require privileged operators, malicious infrastructure, or non-production artifacts.

## Required Impacts
{HYPERBRIDGE_ALLOWED_IMPACT_SCOPE}

{HYPERBRIDGE_AUDIT_PIVOTS}

## Review Path
1. Trace the exact verification, routing, dispatch, settlement, withdrawal, refund, or claim path.
2. Compare the intended chain, route, origin, beneficiary, amount, receipt, commitment, or balance to the actual stored or executed result.
3. Name the wrong header, state root, receipt marker, nonce, beneficiary, amount, balance, approval, queue marker, code state, or effective origin.
4. Reject if duplicate guards, proof checks, filter checks, auth checks, queue semantics, or accounting invariants already stop the path.

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
    Generate a cross-project analog scan prompt for Polkadot SDK issues.
    """
    prompt = f"""# POLKADOT SDK ANALOG SCAN

## External Report
{report}

## Task
Use the external report only as a bug-class seed. Reason only from this repository and find a real local analog in proof verification, message routing,
queue handling, public dispatch wrappers, contracts or revive execution, staking or asset accounting, treasury or reward payouts, or Snowbridge delivery flow.

## Required Impacts
{HYPERBRIDGE_ALLOWED_IMPACT_SCOPE}

{HYPERBRIDGE_AUDIT_PIVOTS}

## Method
- First reduce the external report to its core broken invariant and attacker primitive.
- Internally generate 2 to 4 candidate Polkadot SDK paths, then keep only the strongest one with exact file and function support.
- Prefer public-entrypoint paths that let an unprivileged attacker cause false state acceptance, unauthorized execution, wrong beneficiary or amount,
  duplicate settlement or claim, fund loss or lock, or public underpriced work with chain or bridge impact.
- Reject anything that needs a malicious peer, node, relayer, prover, admin, governance actor, validator, collator, leaked key, or front-run-only conditions.
- Name the exact corrupted value and show why existing guards do not stop the path.
- Do not answer with uncertainty, missing-context, or external-protocol analysis. Either produce a concrete local issue from repository evidence or return
  `#NoVulnerability found for this question.`
- If no locally provable analog survives these checks, return `#NoVulnerability found for this question.`

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
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict Polkadot SDK validation prompt for security claims.
    """
    prompt = f"""# POLKADOT SDK CLAIM VALIDATION

## Security Claim
{report}

## Rules
- Validate only the submitted claim against production Polkadot SDK and Snowbridge bridge, runtime, pallet, contract, and support-crate logic in this repository.
- Do not widen the claim, change the target scope, or raise severity without evidence.
- A valid issue must come from an unprivileged external attacker using public extrinsics, proof or message submission, runtime APIs, callbacks,
  contract calls, or settlement inputs exposed by scoped code.
- Reject malicious peer or node behavior, compromised relayer or prover assumptions, leaked keys, privileged governance or validator powers,
  off-repo infra control, front-run-only claims, tests, mocks, docs, readmes, generated files, `.toml`, and disabled configs.
- The final impact must match one `target_scopes` item or the Polkadot SDK impact gate below and must name the exact corrupted value.

## Required Impacts
{HYPERBRIDGE_ALLOWED_IMPACT_SCOPE}

{HYPERBRIDGE_AUDIT_PIVOTS}

## Required Checks
1. Exact file and function references in scoped code.
2. A clear invariant tied to proof authenticity, route binding, one-time settlement, custody, payout, beneficiary correctness, origin correctness, or cost correctness.
3. A reachable exploit path from attacker input to bad state, bad execution, bad payout, duplicate effect, or permanent lock.
4. Existing guards reviewed and shown insufficient.
5. Exact wrong value named: header, state root, authority set, receipt, nonce, beneficiary, amount, balance, approval, queue marker, code state, or effective origin.
6. A reproducible proof path via Rust unit, integration, property, or fuzz-style testing.

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
