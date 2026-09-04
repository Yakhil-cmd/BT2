import json
import os

from decouple import config

# todo: if scope_files is: 500 > 50, 300 > 30 , 100 > 10
MAX_REPO = 20
# todo: the GitLab namespace/project path, for example group/project
SOURCE_REPO = 'stacks-network/stacks-core'
# todo: the name of the repository
REPO_NAME = 'stacks-core'

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
    # LENS: STACKING, BONDS AND REWARD ACCOUNTING (POX-5 / sBTC).
    # Stacks locks STX and sBTC to secure the chain and pays sBTC rewards. The files
    # below sit on the path from an attacker-supplied contract-call - stake,
    # register-for-bond, unstake, claim-rewards, the signer-manager trait, an L1 Bitcoin
    # lockup proof - to one of three decisions: does locked STX/sBTC equal what the
    # staker committed, do rewards paid equal rewards earned, and can locked value be
    # unlocked exactly once by exactly its owner. A question belongs here only if it can
    # be closed by an equality between value committed and value moved or unlocked.
    # =================================================================================
    # -- The staking contract: every public entry point --------------------------------
    # pox-5 owns stake / register-for-bond / unstake / unstake-sbtc / stake-update /
    # claim-rewards, the reentrancy guard around the signer-manager trait, the reward
    # settlement math, and the Clarity-Bitcoin L1 lockup proof verification.

    # -- clarity-types: Clarity value, type and effect model -------------------------------
    "clarity-types/src/effects/asset_map.rs",
    "clarity-types/src/effects/mod.rs",
    "clarity-types/src/errors/mod.rs",
    "clarity-types/src/lib.rs",
    "clarity-types/src/representations.rs",
    "clarity-types/src/types/mod.rs",
    "clarity-types/src/types/serialization.rs",
    "clarity-types/src/types/signatures.rs",
    "clarity-types/src/version.rs",

    # -- clarity: the Clarity language, analyser, interpreter, costs and database ----------
    "clarity/src/libclarity.rs",
    "clarity/src/vm/analysis/analysis_db.rs",
    "clarity/src/vm/analysis/arithmetic_checker/mod.rs",
    "clarity/src/vm/analysis/contract_interface_builder/mod.rs",
    "clarity/src/vm/analysis/errors.rs",
    "clarity/src/vm/analysis/mod.rs",
    "clarity/src/vm/analysis/read_only_checker/mod.rs",
    "clarity/src/vm/analysis/trait_checker/mod.rs",
    "clarity/src/vm/analysis/type_checker/contexts.rs",
    "clarity/src/vm/analysis/type_checker/mod.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/contexts.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/mod.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/natives/assets.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/natives/maps.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/natives/mod.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/natives/options.rs",
    "clarity/src/vm/analysis/type_checker/v2_05/natives/sequences.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/contexts.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/mod.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/assets.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/conversions.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/maps.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/mod.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/options.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/post_conditions.rs",
    "clarity/src/vm/analysis/type_checker/v2_1/natives/sequences.rs",
    "clarity/src/vm/analysis/types.rs",
    "clarity/src/vm/ast/definition_sorter/mod.rs",
    "clarity/src/vm/ast/errors.rs",
    "clarity/src/vm/ast/expression_identifier/mod.rs",
    "clarity/src/vm/ast/mod.rs",
    "clarity/src/vm/ast/parser/mod.rs",
    "clarity/src/vm/ast/parser/v1.rs",
    "clarity/src/vm/ast/parser/v2/lexer/error.rs",
    "clarity/src/vm/ast/parser/v2/lexer/mod.rs",
    "clarity/src/vm/ast/parser/v2/lexer/token.rs",
    "clarity/src/vm/ast/parser/v2/mod.rs",
    "clarity/src/vm/ast/stack_depth_checker.rs",
    "clarity/src/vm/ast/sugar_expander/mod.rs",
    "clarity/src/vm/ast/traits_resolver/mod.rs",
    "clarity/src/vm/ast/types.rs",
    "clarity/src/vm/callables.rs",
    "clarity/src/vm/clarity.rs",
    "clarity/src/vm/contexts.rs",
    "clarity/src/vm/contracts.rs",
    "clarity/src/vm/costs/constants.rs",
    "clarity/src/vm/costs/cost_functions.rs",
    "clarity/src/vm/costs/costs_1.rs",
    "clarity/src/vm/costs/costs_2.rs",
    "clarity/src/vm/costs/costs_2_testnet.rs",
    "clarity/src/vm/costs/costs_3.rs",
    "clarity/src/vm/costs/costs_4.rs",
    "clarity/src/vm/costs/costs_5.rs",
    "clarity/src/vm/costs/errors.rs",
    "clarity/src/vm/costs/execution_cost.rs",
    "clarity/src/vm/costs/mod.rs",
    "clarity/src/vm/database/caching/mod.rs",
    "clarity/src/vm/database/caching/weight_limited_fifo.rs",
    "clarity/src/vm/database/clarity_db.rs",
    "clarity/src/vm/database/clarity_store.rs",
    "clarity/src/vm/database/key_value_wrapper.rs",
    "clarity/src/vm/database/mod.rs",
    "clarity/src/vm/database/sqlite.rs",
    "clarity/src/vm/database/structures.rs",
    "clarity/src/vm/diagnostic.rs",
    "clarity/src/vm/errors.rs",
    "clarity/src/vm/events.rs",
    "clarity/src/vm/functions/arithmetic.rs",
    "clarity/src/vm/functions/assets.rs",
    "clarity/src/vm/functions/bitcoin.rs",
    "clarity/src/vm/functions/boolean.rs",
    "clarity/src/vm/functions/conversions.rs",
    "clarity/src/vm/functions/crypto.rs",
    "clarity/src/vm/functions/database.rs",
    "clarity/src/vm/functions/define.rs",
    "clarity/src/vm/functions/mod.rs",
    "clarity/src/vm/functions/options.rs",
    "clarity/src/vm/functions/post_conditions.rs",
    "clarity/src/vm/functions/principals.rs",
    "clarity/src/vm/functions/sequences.rs",
    "clarity/src/vm/functions/tuples.rs",
    "clarity/src/vm/hooks/internals.rs",
    "clarity/src/vm/hooks/mod.rs",
    "clarity/src/vm/hooks/trace.rs",
    "clarity/src/vm/mod.rs",
    "clarity/src/vm/representations.rs",
    "clarity/src/vm/resource_limiter.rs",
    "clarity/src/vm/tooling/mod.rs",
    "clarity/src/vm/types/mod.rs",
    "clarity/src/vm/types/serialization.rs",
    "clarity/src/vm/types/signatures.rs",
    "clarity/src/vm/variables.rs",
    "clarity/src/vm/version.rs",

    # -- stacks-codec: transaction and message wire encoding -------------------------------
    "stacks-codec/src/lib.rs",
    "stacks-codec/src/strings.rs",
    "stacks-codec/src/transaction.rs",

    # -- crates/stacks-transactions: standalone transaction and post-condition checks ------
    "crates/stacks-transactions/src/lib.rs",

    # -- stacks-common: addresses, hashing, secp256k1, codec and shared utils --------------
    "stacks-common/src/address/b58.rs",
    "stacks-common/src/address/c32.rs",
    "stacks-common/src/address/c32_old.rs",
    "stacks-common/src/address/mod.rs",
    "stacks-common/src/alloc_tracker.rs",
    "stacks-common/src/bitvec.rs",
    "stacks-common/src/codec/macros.rs",
    "stacks-common/src/codec/mod.rs",
    "stacks-common/src/libcommon.rs",
    "stacks-common/src/types/chainstate.rs",
    "stacks-common/src/types/mod.rs",
    "stacks-common/src/types/net.rs",
    "stacks-common/src/types/sqlite.rs",
    "stacks-common/src/util/chunked_encoding.rs",
    "stacks-common/src/util/db.rs",
    "stacks-common/src/util/ed25519.rs",
    "stacks-common/src/util/hash.rs",
    "stacks-common/src/util/log.rs",
    "stacks-common/src/util/lru_cache.rs",
    "stacks-common/src/util/macros.rs",
    "stacks-common/src/util/mod.rs",
    "stacks-common/src/util/pair.rs",
    "stacks-common/src/util/pipe.rs",
    "stacks-common/src/util/retry.rs",
    "stacks-common/src/util/secp256k1/mod.rs",
    "stacks-common/src/util/secp256k1/native.rs",
    "stacks-common/src/util/secp256k1/wasm.rs",
    "stacks-common/src/util/secp256r1.rs",
    "stacks-common/src/util/serde_serializers.rs",
    "stacks-common/src/util/uint.rs",
    "stacks-common/src/util/vrf.rs",

    # -- libsigner: signer transport, events and v0 messages -------------------------------
    "libsigner/src/error.rs",
    "libsigner/src/events.rs",
    "libsigner/src/http.rs",
    "libsigner/src/libsigner.rs",
    "libsigner/src/runloop.rs",
    "libsigner/src/session.rs",
    "libsigner/src/signer_set.rs",
    "libsigner/src/v0/messages.rs",
    "libsigner/src/v0/mod.rs",
    "libsigner/src/v0/signer_state.rs",

    # -- libstackerdb: StackerDB chunk signing and verification ----------------------------
    "libstackerdb/src/libstackerdb.rs",

    # -- pox-locking: the Rust side that locks and unlocks STX for PoX/stacking ------------
    "pox-locking/src/events.rs",
    "pox-locking/src/events_24.rs",
    "pox-locking/src/lib.rs",
    "pox-locking/src/pox_1.rs",
    "pox-locking/src/pox_2.rs",
    "pox-locking/src/pox_3.rs",
    "pox-locking/src/pox_4.rs",
    "pox-locking/src/pox_5.rs",

    # -- stacks-signer: the Nakamoto signer decision logic and chainstate view -------------
    "stacks-signer/src/chainstate/mod.rs",
    "stacks-signer/src/chainstate/v1.rs",
    "stacks-signer/src/chainstate/v2.rs",
    "stacks-signer/src/cli.rs",
    "stacks-signer/src/client/mod.rs",
    "stacks-signer/src/client/stackerdb.rs",
    "stacks-signer/src/client/stacks_client.rs",
    "stacks-signer/src/config.rs",
    "stacks-signer/src/lib.rs",
    "stacks-signer/src/main.rs",
    "stacks-signer/src/monitor_signers.rs",
    "stacks-signer/src/monitoring/mod.rs",
    "stacks-signer/src/monitoring/prometheus.rs",
    "stacks-signer/src/monitoring/server.rs",
    "stacks-signer/src/runloop.rs",
    "stacks-signer/src/signerdb.rs",
    "stacks-signer/src/utils.rs",
    "stacks-signer/src/v0/mod.rs",
    "stacks-signer/src/v0/signer.rs",
    "stacks-signer/src/v0/signer_state.rs",

    # -- stacks-node: the node binary, run loops, miner, burnchain and event dispatch ------
    "stacks-node/src/burnchains/bitcoin/core_controller.rs",
    "stacks-node/src/burnchains/bitcoin/mod.rs",
    "stacks-node/src/burnchains/bitcoin_regtest_controller.rs",
    "stacks-node/src/burnchains/mod.rs",
    "stacks-node/src/burnchains/rpc/bitcoin_rpc_client/mod.rs",
    "stacks-node/src/burnchains/rpc/mod.rs",
    "stacks-node/src/burnchains/rpc/rpc_transport/mod.rs",
    "stacks-node/src/event_dispatcher.rs",
    "stacks-node/src/event_dispatcher/db.rs",
    "stacks-node/src/event_dispatcher/payloads.rs",
    "stacks-node/src/event_dispatcher/stacker_db.rs",
    "stacks-node/src/event_dispatcher/worker.rs",
    "stacks-node/src/globals.rs",
    "stacks-node/src/keychain.rs",
    "stacks-node/src/main.rs",
    "stacks-node/src/monitoring/mod.rs",
    "stacks-node/src/monitoring/prometheus.rs",
    "stacks-node/src/nakamoto_node.rs",
    "stacks-node/src/nakamoto_node/miner.rs",
    "stacks-node/src/nakamoto_node/miner_db.rs",
    "stacks-node/src/nakamoto_node/peer.rs",
    "stacks-node/src/nakamoto_node/relayer.rs",
    "stacks-node/src/nakamoto_node/signer_coordinator.rs",
    "stacks-node/src/nakamoto_node/stackerdb_listener.rs",
    "stacks-node/src/neon_node.rs",
    "stacks-node/src/node.rs",
    "stacks-node/src/operations.rs",
    "stacks-node/src/run_loop/boot_nakamoto.rs",
    "stacks-node/src/run_loop/helium.rs",
    "stacks-node/src/run_loop/mod.rs",
    "stacks-node/src/run_loop/nakamoto.rs",
    "stacks-node/src/run_loop/neon.rs",
    "stacks-node/src/syncctl.rs",
    "stacks-node/src/tenure.rs",

    # -- stackslib: consensus, chainstate, the Clarity VM host, burn ops and the P2P/RPC network ----
    "stackslib/src/burnchains/bitcoin/address.rs",
    "stackslib/src/burnchains/bitcoin/bits.rs",
    "stackslib/src/burnchains/bitcoin/blocks.rs",
    "stackslib/src/burnchains/bitcoin/indexer.rs",
    "stackslib/src/burnchains/bitcoin/keys.rs",
    "stackslib/src/burnchains/bitcoin/messages.rs",
    "stackslib/src/burnchains/bitcoin/mod.rs",
    "stackslib/src/burnchains/bitcoin/network.rs",
    "stackslib/src/burnchains/bitcoin/spv.rs",
    "stackslib/src/burnchains/burnchain.rs",
    "stackslib/src/burnchains/db.rs",
    "stackslib/src/burnchains/indexer.rs",
    "stackslib/src/burnchains/mod.rs",
    "stackslib/src/chainstate/burn/atc.rs",
    "stackslib/src/chainstate/burn/db/mod.rs",
    "stackslib/src/chainstate/burn/db/processing.rs",
    "stackslib/src/chainstate/burn/db/sortdb.rs",
    "stackslib/src/chainstate/burn/distribution.rs",
    "stackslib/src/chainstate/burn/mod.rs",
    "stackslib/src/chainstate/burn/operations/delegate_stx.rs",
    "stackslib/src/chainstate/burn/operations/leader_block_commit.rs",
    "stackslib/src/chainstate/burn/operations/leader_key_register.rs",
    "stackslib/src/chainstate/burn/operations/mod.rs",
    "stackslib/src/chainstate/burn/operations/stack_stx.rs",
    "stackslib/src/chainstate/burn/operations/transfer_stx.rs",
    "stackslib/src/chainstate/burn/operations/vote_for_aggregate_key.rs",
    "stackslib/src/chainstate/burn/sortition.rs",
    "stackslib/src/chainstate/coordinator/comm.rs",
    "stackslib/src/chainstate/coordinator/mod.rs",
    "stackslib/src/chainstate/mod.rs",
    "stackslib/src/chainstate/nakamoto/coordinator/mod.rs",
    "stackslib/src/chainstate/nakamoto/keys.rs",
    "stackslib/src/chainstate/nakamoto/miner.rs",
    "stackslib/src/chainstate/nakamoto/mod.rs",
    "stackslib/src/chainstate/nakamoto/shadow.rs",
    "stackslib/src/chainstate/nakamoto/signer_set.rs",
    "stackslib/src/chainstate/nakamoto/staging_blocks.rs",
    "stackslib/src/chainstate/nakamoto/tenure.rs",
    "stackslib/src/chainstate/stacks/address.rs",
    "stackslib/src/chainstate/stacks/auth.rs",
    "stackslib/src/chainstate/stacks/block.rs",
    "stackslib/src/chainstate/stacks/boot/bns.clar",
    "stackslib/src/chainstate/stacks/boot/contract_tests.rs",
    "stackslib/src/chainstate/stacks/boot/cost-voting.clar",
    "stackslib/src/chainstate/stacks/boot/costs-2.clar",
    "stackslib/src/chainstate/stacks/boot/costs-3.clar",
    "stackslib/src/chainstate/stacks/boot/costs-4.clar",
    "stackslib/src/chainstate/stacks/boot/costs.clar",
    "stackslib/src/chainstate/stacks/boot/docs.rs",
    "stackslib/src/chainstate/stacks/boot/genesis.clar",
    "stackslib/src/chainstate/stacks/boot/lockup.clar",
    "stackslib/src/chainstate/stacks/boot/mod.rs",
    "stackslib/src/chainstate/stacks/boot/pox-2.clar",
    "stackslib/src/chainstate/stacks/boot/pox-3.clar",
    "stackslib/src/chainstate/stacks/boot/pox-4.clar",
    "stackslib/src/chainstate/stacks/boot/pox-5.clar",
    "stackslib/src/chainstate/stacks/boot/pox-mainnet.clar",
    "stackslib/src/chainstate/stacks/boot/pox.clar",
    "stackslib/src/chainstate/stacks/boot/pox_2_tests.rs",
    "stackslib/src/chainstate/stacks/boot/pox_3_tests.rs",
    "stackslib/src/chainstate/stacks/boot/pox_4_tests.rs",
    "stackslib/src/chainstate/stacks/boot/signers-0-xxx.clar",
    "stackslib/src/chainstate/stacks/boot/signers-1-xxx.clar",
    "stackslib/src/chainstate/stacks/boot/signers-voting.clar",
    "stackslib/src/chainstate/stacks/boot/signers.clar",
    "stackslib/src/chainstate/stacks/boot/signers_tests.rs",
    "stackslib/src/chainstate/stacks/boot/sip-031.clar",
    "stackslib/src/chainstate/stacks/db/accounts.rs",
    "stackslib/src/chainstate/stacks/db/blocks.rs",
    "stackslib/src/chainstate/stacks/db/contracts.rs",
    "stackslib/src/chainstate/stacks/db/headers.rs",
    "stackslib/src/chainstate/stacks/db/mod.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/blocks.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/burnchain.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/clarity.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/common.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/fork_storage.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/index.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/mod.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/sortition.rs",
    "stackslib/src/chainstate/stacks/db/snapshot/spv.rs",
    "stackslib/src/chainstate/stacks/db/transactions.rs",
    "stackslib/src/chainstate/stacks/db/unconfirmed.rs",
    "stackslib/src/chainstate/stacks/events.rs",
    "stackslib/src/chainstate/stacks/index/bits.rs",
    "stackslib/src/chainstate/stacks/index/blob_layout.rs",
    "stackslib/src/chainstate/stacks/index/cache.rs",
    "stackslib/src/chainstate/stacks/index/file.rs",
    "stackslib/src/chainstate/stacks/index/marf.rs",
    "stackslib/src/chainstate/stacks/index/mod.rs",
    "stackslib/src/chainstate/stacks/index/node.rs",
    "stackslib/src/chainstate/stacks/index/profile.rs",
    "stackslib/src/chainstate/stacks/index/proofs.rs",
    "stackslib/src/chainstate/stacks/index/squash.rs",
    "stackslib/src/chainstate/stacks/index/squash/node_store.rs",
    "stackslib/src/chainstate/stacks/index/squash/stream.rs",
    "stackslib/src/chainstate/stacks/index/storage.rs",
    "stackslib/src/chainstate/stacks/index/trie.rs",
    "stackslib/src/chainstate/stacks/index/trie_sql.rs",
    "stackslib/src/chainstate/stacks/miner.rs",
    "stackslib/src/chainstate/stacks/mod.rs",
    "stackslib/src/chainstate/stacks/sbtc.rs",
    "stackslib/src/chainstate/stacks/transaction.rs",
    "stackslib/src/clarity_vm/clarity.rs",
    "stackslib/src/clarity_vm/database/ephemeral.rs",
    "stackslib/src/clarity_vm/database/marf.rs",
    "stackslib/src/clarity_vm/database/mod.rs",
    "stackslib/src/clarity_vm/mod.rs",
    "stackslib/src/clarity_vm/special.rs",
    "stackslib/src/config/chain_data.rs",
    "stackslib/src/config/mod.rs",
    "stackslib/src/core/mempool.rs",
    "stackslib/src/core/mod.rs",
    "stackslib/src/core/nonce_cache.rs",
    "stackslib/src/cost_estimates/fee_medians.rs",
    "stackslib/src/cost_estimates/fee_rate_fuzzer.rs",
    "stackslib/src/cost_estimates/fee_scalar.rs",
    "stackslib/src/cost_estimates/metrics.rs",
    "stackslib/src/cost_estimates/mod.rs",
    "stackslib/src/cost_estimates/pessimistic.rs",
    "stackslib/src/deps/mod.rs",
    "stackslib/src/lib.rs",
    "stackslib/src/monitoring/mod.rs",
    "stackslib/src/monitoring/prometheus.rs",
    "stackslib/src/net/api/blockreplay.rs",
    "stackslib/src/net/api/blocksimulate.rs",
    "stackslib/src/net/api/callreadonly.rs",
    "stackslib/src/net/api/fastcallreadonly.rs",
    "stackslib/src/net/api/get_tenure_tip_meta.rs",
    "stackslib/src/net/api/get_tenures_fork_info.rs",
    "stackslib/src/net/api/getaccount.rs",
    "stackslib/src/net/api/getattachment.rs",
    "stackslib/src/net/api/getattachmentsinv.rs",
    "stackslib/src/net/api/getblock.rs",
    "stackslib/src/net/api/getblock_v3.rs",
    "stackslib/src/net/api/getblockbyheight.rs",
    "stackslib/src/net/api/getclaritymarfvalue.rs",
    "stackslib/src/net/api/getclaritymetadata.rs",
    "stackslib/src/net/api/getconstantval.rs",
    "stackslib/src/net/api/getcontractabi.rs",
    "stackslib/src/net/api/getcontractsrc.rs",
    "stackslib/src/net/api/getdatavar.rs",
    "stackslib/src/net/api/getheaders.rs",
    "stackslib/src/net/api/gethealth.rs",
    "stackslib/src/net/api/getinfo.rs",
    "stackslib/src/net/api/getistraitimplemented.rs",
    "stackslib/src/net/api/getmapentry.rs",
    "stackslib/src/net/api/getmicroblocks_confirmed.rs",
    "stackslib/src/net/api/getmicroblocks_indexed.rs",
    "stackslib/src/net/api/getmicroblocks_unconfirmed.rs",
    "stackslib/src/net/api/getneighbors.rs",
    "stackslib/src/net/api/getpoxinfo.rs",
    "stackslib/src/net/api/getsigner.rs",
    "stackslib/src/net/api/getsortition.rs",
    "stackslib/src/net/api/getstackerdbchunk.rs",
    "stackslib/src/net/api/getstackerdbmetadata.rs",
    "stackslib/src/net/api/getstackers.rs",
    "stackslib/src/net/api/getstxtransfercost.rs",
    "stackslib/src/net/api/gettenure.rs",
    "stackslib/src/net/api/gettenureblocks.rs",
    "stackslib/src/net/api/gettenureblocksbyhash.rs",
    "stackslib/src/net/api/gettenureblocksbyheight.rs",
    "stackslib/src/net/api/gettenureinfo.rs",
    "stackslib/src/net/api/gettenuretip.rs",
    "stackslib/src/net/api/gettransaction.rs",
    "stackslib/src/net/api/gettransaction_unconfirmed.rs",
    "stackslib/src/net/api/liststackerdbreplicas.rs",
    "stackslib/src/net/api/mod.rs",
    "stackslib/src/net/api/postblock.rs",
    "stackslib/src/net/api/postblock_proposal.rs",
    "stackslib/src/net/api/postblock_v3.rs",
    "stackslib/src/net/api/postfeerate.rs",
    "stackslib/src/net/api/postmempoolquery.rs",
    "stackslib/src/net/api/postmicroblock.rs",
    "stackslib/src/net/api/poststackerdbchunk.rs",
    "stackslib/src/net/api/posttransaction.rs",
    "stackslib/src/net/api/read_only/mod.rs",
    "stackslib/src/net/api/read_only/parse.rs",
    "stackslib/src/net/api/txsimulate.rs",
    "stackslib/src/net/asn.rs",
    "stackslib/src/net/atlas/db.rs",
    "stackslib/src/net/atlas/download.rs",
    "stackslib/src/net/atlas/mod.rs",
    "stackslib/src/net/chat.rs",
    "stackslib/src/net/codec.rs",
    "stackslib/src/net/connection.rs",
    "stackslib/src/net/db.rs",
    "stackslib/src/net/dns.rs",
    "stackslib/src/net/download/epoch2x.rs",
    "stackslib/src/net/download/mod.rs",
    "stackslib/src/net/download/nakamoto/download_state_machine.rs",
    "stackslib/src/net/download/nakamoto/mod.rs",
    "stackslib/src/net/download/nakamoto/tenure.rs",
    "stackslib/src/net/download/nakamoto/tenure_downloader.rs",
    "stackslib/src/net/download/nakamoto/tenure_downloader_set.rs",
    "stackslib/src/net/download/nakamoto/tenure_downloader_unconfirmed.rs",
    "stackslib/src/net/http/common.rs",
    "stackslib/src/net/http/error.rs",
    "stackslib/src/net/http/mod.rs",
    "stackslib/src/net/http/request.rs",
    "stackslib/src/net/http/response.rs",
    "stackslib/src/net/http/stream.rs",
    "stackslib/src/net/httpcore.rs",
    "stackslib/src/net/inv/epoch2x.rs",
    "stackslib/src/net/inv/mod.rs",
    "stackslib/src/net/inv/nakamoto.rs",
    "stackslib/src/net/mempool/mod.rs",
    "stackslib/src/net/mod.rs",
    "stackslib/src/net/neighbors/comms.rs",
    "stackslib/src/net/neighbors/db.rs",
    "stackslib/src/net/neighbors/mod.rs",
    "stackslib/src/net/neighbors/neighbor.rs",
    "stackslib/src/net/neighbors/rpc.rs",
    "stackslib/src/net/neighbors/walk.rs",
    "stackslib/src/net/p2p.rs",
    "stackslib/src/net/poll.rs",
    "stackslib/src/net/prune.rs",
    "stackslib/src/net/relay.rs",
    "stackslib/src/net/rpc.rs",
    "stackslib/src/net/server.rs",
    "stackslib/src/net/stackerdb/config.rs",
    "stackslib/src/net/stackerdb/db.rs",
    "stackslib/src/net/stackerdb/mod.rs",
    "stackslib/src/net/stackerdb/sync.rs",
    "stackslib/src/net/unsolicited.rs",
    "stackslib/src/util_lib/bloom.rs",
    "stackslib/src/util_lib/boot.rs",
    "stackslib/src/util_lib/db.rs",
    "stackslib/src/util_lib/mod.rs",
    "stackslib/src/util_lib/signed_structured_data.rs",
    "stackslib/src/util_lib/strings.rs",

    # =================================================================================
    # NOT AUDITED (excluded from every variant): tests, mocks and *test* files; fuzz and
    # bench harnesses; test_util and the hooks/testing render helpers; docs/ and README;
    # config, *.toml and CHANGELOG; generated tables (stx-genesis, genesis_data.rs) and
    # build.rs; vendored third-party code under deps_common/ (bitcoin, httparse, bech32,
    # ctrlc); the contrib/ tools and stacks-profiler; sample/ example contracts; and the
    # *-testnet / *.tests.clar network- and test-only contract bodies. A defect in any of
    # these is only in scope when it is reachable from the audited code above.
    # =================================================================================
]


target_scopes = [
    "Critical. LOCKED STX MUST EQUAL WHAT THE STAKER COMMITTED. `stake` in pox-5.clar reads `(stx-account tx-sender)`, computes `total-balance` and calls the signer-manager trait, then Clarity returns a tuple that `pox_5.rs` `parse_pox_stake_result` turns into a real `STXBalance` lock via `handle_lockup_pox_v5` / `pox_lock_v5`. Probe every gap between the amount the contract validated and the amount `structures.rs` actually locks: a `lock_amount` larger than `amount_unlocked`, a rollover in `handle_stake_on_locked_account` that rolls forward a higher or lower amount than the response tuple states, an `unlock_height` in the past, a `stake-update` that increases locked STX without a matching balance debit, an error response that `locking_error_to_vm_error` swallows so the Clarity call succeeds but no lock is written. Identity: STX locked in the account's `STXBalance` after `stake` == the `amount-ustx` the pox-5 body validated against the account's spendable balance.",

    "Critical. sBTC REWARDS PAID MUST EQUAL sBTC REWARDS EARNED. `claim-rewards` and `claim-staker-rewards-for-signer` fold `update-claimable-bond-rewards`, settle with `settle-rewards` / `settle-staker-rewards`, transfer sBTC through `as-contract?` with a `with-ft` allowance, then decrement `last-accounted-rewards-only`. Probe the settlement: `compute-earned-rewards` using `get-rewards-per-token-for-cycle` against a per-token snapshot the claimer can advance, a bond period listed twice in the `(list 6 uint)` so its reward is folded twice, a `reward-cycle` claimed before it settled, `PRECISION` rounding that leaves dust claimable every cycle, a `settle-staker-rewards` that zeroes `staker-unclaimed-rewards-for-cycle` after the transfer so a reentrant path re-reads the old value. Identity: sBTC transferred out of pox-5 for a (signer, staker, cycle) == the rewards that (signer, staker, cycle) actually accrued, summed once.",

    "Critical. THE REENTRANCY GUARD IS THE ONLY THING BETWEEN A TRAIT CALL AND DOUBLE-COUNTING. Every stake path calls the caller-supplied `signer-manager-trait.validate-stake!`, guarded by `signer-manager-validate-stake` setting `signer-manager-call-active`; `validate-no-reentrancy` guards the claim and unstake paths. An unprivileged staker deploys the signer-manager contract, so `validate-stake!` runs attacker code with pox-5 mid-mutation. Show a path where the guard is not held for the whole critical section - a public function that mutates next-cycle state before setting the flag, a `claim-rewards` that transfers sBTC and only then updates `last-accounted-rewards-only`, a trait call that re-enters a sibling entry point the guard does not cover - so the staker's own contract re-enters and stakes, unstakes or claims twice against one commitment. Identity: the number of times a commitment or reward is counted across one transaction == one, for every reachable re-entry through `validate-stake!`.",

    "Critical. THE L1 BITCOIN LOCKUP PROOF DECIDES sBTC OUT OF THIN AIR. `register-for-bond` accepts `btc-lockup` as either an L1 proof or an sBTC amount; on the L1 path `verify-l1-lockups` folds `validate-l1-lockup` over up to 10 outputs, each parsing a Bitcoin header with `parse-block-header`, verifying inclusion with `verify-block-header` / `get-burn-block-info?`, checking the timelock script built by `construct-lockup-script`, and summing `amount` while `seen-outpoints` rejects duplicates. Show an unprivileged staker crediting sats they did not lock: an output whose `amount` field differs from the real Bitcoin output value, a `header` for a burn block that `get-burn-block-info?` cannot bind to the claimed `height`, a merkle proof with `leaf-hashes` that validates a transaction from a different block, a `staker-unlock-bytes` subscript that does not commit to `tx-sender`, an `unlock-burn-height` below `minimum-unlock-height`, two outputs with different indexes but the same value double-summed. Identity: sats credited to a bond by `verify-l1-lockups` == sats actually locked to the staker's timelock script in a confirmed Bitcoin transaction.",

    "Critical. UNSTAKING sBTC MUST NOT EXCEED WHAT WAS STAKED. `unstake-sbtc` reads `protocol-bond-memberships`, computes `new-amount-sats` only when `amount-to-withdrawal-sats <= current-amount-sats`, checks the membership is not an L1 lock, runs `validate-no-reentrancy`, then transfers sBTC through `as-contract?`. Probe the accounting across cycles: `first-changed-reward-cycle` from `clamp` excluding the current cycle so custody is released while still counted for rewards, `get-total-sbtc-staked` not decremented in lockstep with the per-staker amount, a withdrawal during the prepare phase that `verify-not-prepare-phase` should block, a membership whose `signer` no longer matches so `ERR_INVALID_OLD_SIGNER_MANAGER` is dodged, a rollover in `register-for-bond` that refunds `old-sbtc` while the new bond still custodies it. Identity: sBTC transferred out by `unstake-sbtc` plus sBTC still custodied for the staker == sBTC the staker originally staked to that bond.",

    "Critical. STX UNLOCKS EXACTLY ONCE, AT THE HEIGHT THE STAKER CHOSE. `stake` derives `unlock-cycle` from `first-reward-cycle + num-cycles`, `check-pox-lock-period` bounds `num-cycles`, and the coordinator's `handle_pox_cycle_start_pox_5` / `handle_pox_cycle_missed_unlocks` (signer_set.rs, boot/mod.rs) release locks at cycle boundaries by writing `STXBalance` unlock heights. Show a staker whose STX unlocks early or stays locked forever: a `num-cycles` that overflows `unlock-cycle`, a `stake-update` extending a lock whose old unlock height already passed so `handle_stake_lockup_update_pox_v5` returns an internal error but leaves state changed, a missed-unlock handler that skips an account, an `announce-l1-early-exit` that shifts the unlock height without a matching L1 event, a start-burn-height in the past so `specified-reward-cycle` precedes `first-reward-cycle`. Identity: the burn height at which an account's `STXBalance` becomes spendable == the unlock height the accepted `stake` / `stake-update` committed.",

    "High. THE SIGNER-KEY AUTHORIZATION SIGNS EXACTLY ONE STACKING ACTION. `register-signer` / `grant-signer-key` and `verify-signer-key-grant` check a SIP-018 signature over `get-signer-grant-message-hash`, built from the `POX_5_SIGNER_DOMAIN` (name `pox-5-signer`, version, `chain-id`) and the grant fields, with `ERR_SIGNER_KEY_GRANT_USED` guarding replay via `used` state. Show a signature an unprivileged staker replays or repurposes: a message hash that omits a field the contract acts on (amount, reward cycle, staker, bond index), a grant reused across two bonds because the `used` key does not include every distinguishing field, a domain that omits `chain-id` so a testnet signature works on mainnet, a `secp256k1-recover?` result whose low-S is not enforced so a second malleable signature bypasses the used-set. Identity: every stacking action authorised by a signer key == exactly one grant the signer signed for that (staker, amount, cycle, chain).",

    "Critical. BURNCHAIN STACKING OPS MOVE STX FROM AN OFF-CHAIN IDENTITY. `stack_stx.rs`, `delegate_stx.rs` and `transfer_stx.rs` `parse_from_tx` derive `sender` from the first Bitcoin input via `get_sender_txid` / `get_input_tx_ref(0)` and `check` validates amounts and outputs; the Stacks node then applies the op as if that Stacks address authorised it. Show an op that moves or locks STX the deriving address did not authorise: a `TransferStxOp` whose `sender == recipient` slips past the check, a `StackStxOp` whose parsed `signer_key` is `None` yet still locks, a `PreStxOp`/`StackStxOp` pairing where the pre-op sender differs from the stack sender, a `DelegateStxOp` with a `delegated_ustx` exceeding the sender's balance, a truncated `parse_data` accepted with defaulted fields. Identity: the STX locked or transferred by an applied burnchain op == STX owned by the Stacks address the op's first Bitcoin input maps to, and only with that address's committed parameters.",

    "High. REWARD-SET AND SIGNER-SET WEIGHT MUST EQUAL STAKED STX. `boot/mod.rs` `make_reward_set` / `make_signer_set` / `get_threshold_from_participation` / `get_reward_threshold_and_participation` and `signer_set.rs` `get_signers_weights` derive each cycle's signer weights and PoX threshold from pox-5 stacking state read through `get-reward-set` and the signer linked list. Show a staker who gains signing weight or a reward slot exceeding their locked STX: a stake counted in two cycles by the `signer-set-ll` insertion, a `pox_ustx_threshold` computed from a participation total that includes an already-unlocked staker, a weight rounded up by `PRECISION`, a bond whose sats convert to ustx via `min-ustx-for-sats-amount` at a stale ratio. Identity: the signing weight and reward slots assigned to a principal for a cycle == the STX (or sats-equivalent) that principal has locked and unexpired for that cycle.",

    "Critical. THE MISSING INVARIANT - what nobody built. No assertion ties the sBTC balance pox-5 custodies to the sum of all bond memberships plus the reserve; no check proves `last-accounted-rewards-only` equals the sum of unclaimed rewards across signers and stakers; nothing binds the STX locked across all accounts to the participation total the reward set is computed from; the L1 lockup proof trusts `get-burn-block-info?` for a height the fold never re-checks against the header; a rollover refunds `old-sbtc` on the assumption the old bond is fully released. Identify the FIRST place one of these unstated conservation assumptions is violated by an unprivileged staker with their own STX, their own sBTC and their own signer-manager contract, prove it with a Rust integration test on a booted chainstate that asserts custodied sBTC versus outstanding memberships, or locked STX versus participation, before and after, and show that once the two diverge no cycle boundary can detect or reverse it.",
]


scope_scan = [
]


def question_generator(target_file: str) -> str:
    """
    Generate stacking / bond / reward audit questions for one stacks-core target.

    ```
    target_file format:
    "'File Name: stackslib/src/chainstate/stacks/boot/pox-5.clar -> Scope: Critical. ...'"
    """

    prompt = f"""
    ```

    Generate blockchain-consensus and smart-contract security audit questions for this exact
    stacks-core target:

    {target_file}

    Project focus:
    stacks-core secures the Stacks chain by locking STX and sBTC. Untrusted input enters
    through pox-5 contract-calls an unprivileged account makes - `stake`,
    `register-for-bond`, `unstake`, `unstake-sbtc`, `stake-update`, `claim-rewards` - each
    passing a caller-deployed `signer-manager-trait` contract and, on the bond path, a
    Clarity-Bitcoin L1 lockup proof, plus burnchain `stack-stx` / `delegate-stx` /
    `transfer-stx` operations whose sender is derived from a Bitcoin input. The system
    decides (a) whether STX/sBTC locked equals what the staker committed; (b) whether sBTC
    rewards paid equal rewards earned; (c) whether locked value unlocks exactly once, at the
    chosen height, only for its owner. The pox-5 Clarity result and the `pox-locking` Rust
    lock must agree. Anything locked, unlocked, credited or paid that the contract did not
    validate, or counted twice, is the bug.

    Rules:
    * Treat `File Name:` as the exact file.
    * Treat `Scope:` as the ONLY impact to target.
    * Assume full repo context is accessible.
    * Do not ask for code or say anything is missing.
    * Use exact Clarity and Rust symbols (define-public/-private/-read-only name, map,
      constant, error code, trait, Rust function, struct field) as they appear in the file.
    * EVERY question must close on an equality that must hold across a call. State it
      explicitly. Narrative questions with no stated equality are rejected.
    * Attacker is unprivileged only: any Stacks account with its own STX and sBTC. They may
      deploy the `signer-manager` contract, call any pox-5 entry point, submit L1 lockup
      proofs, craft burnchain stacking ops from Bitcoin inputs they control, and order
      their own transactions.
    * Attacker is NOT the bond admin, pause admin, a miner, a signer with another's key, the
      SIP-031 recipient, or the victim staker. No malicious peer, node, RPC, relayer or
      Bitcoin miner; no compromised dependency; no social engineering.
    * PROGRAM EXCLUSIONS - a question landing in any of these wastes the whole batch:
      - pox.clar, pox-2.clar, pox-3.clar and pox_1/2/3.rs are superseded and OUT OF SCOPE,
        as are README, tests, benches and config.
      - The externally deployed `sbtc-token` contract is out of scope except where pox-5's
        own use of it (allowance, transfer order, recipient) is the flaw.
      - Denial of service, gas griefing, block stuffing, unbounded loops and memory hygiene
        are OUT OF SCOPE.
      - Defects in secp256k1, Bitcoin consensus, or the Clarity VM internals with no exploit
        path through pox-5 or pox-locking are OUT OF SCOPE; a weakness here that steers them
        wrong is fully IN scope.
      - Also excluded: leaked keys, privileged accounts, centralization risk, best-practice
        notes, feature requests, STX/BTC price assumptions, funds sent by mistake, and
        theoretical findings.
    * IN-SCOPE IMPACTS - every question must land on one and name it:
      Critical: theft or unbacked minting of locked STX or sBTC rewards; permanent freezing
      of staked STX or sBTC; unlocking value that was never locked; double-counting a
      commitment or reward.
      High: theft or permanent freezing of protocol reserve or fees; temporary freezing of
      staked funds; gaining signing weight or reward slots exceeding locked value;
      authorising a stacking action the staker or signer never signed.
    * Every question must be a concrete real-world scenario an unprivileged account can
      execute on the deployed chain with their own funds and their own contracts.
    * A revert is a finding only when it permanently strands staked value or lets an
      unbacked lock/credit through - say which.
    * Generate 20 to 40 high-signal questions.
    * At least 70% must land on a Critical impact rather than a High one.
    * Every question must be testable with a Rust integration test on a booted chainstate
      (or a Clarity unit test) locally. Never propose testing on mainnet or a public
      testnet.
    * Avoid generic checklist questions and repeated root causes.
    * Prefer questions that name TWO values that must be equal and ask whether they are: STX
      locked and STX committed, sBTC paid and sBTC earned, sats credited and sats locked on
      Bitcoin, value unlocked and value staked, weight assigned and value locked.

    Known dead ends - do NOT generate questions about these:
    * Anything needing the bond admin, pause admin, a miner, or another staker's key.
    * A bug in the external sbtc-token or in Bitcoin itself with no path through pox-5.
    * Superseded PoX contracts, timing, DoS, gas, or a staker harming only their own stake.
    * Findings only reproducible through tests or tooling.

    Core equalities (each question must close on one):
    * LOCK CONSERVATION: STX/sBTC locked == value the staker committed and owns.
    * REWARD CONSERVATION: sBTC paid for a (signer, staker, cycle) == rewards earned, once.
    * PROOF TRUTH: sats credited by an L1 lockup proof == sats locked in a confirmed
      Bitcoin timelock committed to the staker.
    * SINGLE UNLOCK: value unlocks once, at the committed height, only for its owner.
    * AUTHORITY: every stacking action == one the staker or their signer signed for exactly
      those parameters on this chain.

    Each question must include:
    1. target define-public/-private/-read-only or Rust function;
    2. attacker action (a concrete call with the arguments and trait/proof fields that matter);
    3. preconditions (cycle phase, existing membership, balances, allowlist state);
    4. call sequence through the contract, pox-locking and the coordinator;
    5. the equality that breaks, written explicitly;
    6. scoped impact and whose funds are exposed;
    7. proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Method: function_name] Can an unprivileged ATTACKER_ACTION under PRECONDITIONS trigger CALL_SEQUENCE, breaking the equality EQUALITY, causing scoped impact: SCOPE_IMPACT against PARTY? Proof idea: Rust or Clarity test PARAMETERS asserting LOCK_CONSERVATION, REWARD_CONSERVATION, PROOF_TRUTH, SINGLE_UNLOCK, or AUTHORITY.",
    ]
    """
    return prompt


def audit_format(security_question: str) -> str:
    """
    Generate a stacking / bond / reward exploit-validation prompt for stacks-core.
    """

    prompt = f"""# SECURITY AUDIT PROMPT

## Question
{security_question}

## Rules
- Use existing repo context only. Analyze only this question and scoped impact.
- Attacker is unprivileged only: any Stacks account with its own STX and sBTC who can deploy the signer-manager contract, call any pox-5 entry point, submit L1 lockup proofs, craft burnchain stacking ops from their own Bitcoin inputs, and order their own transactions. They are not the bond admin, pause admin, a miner, a signer with another's key, the SIP-031 recipient or the victim staker.
- Reject malicious peer/node/RPC/relayer/Bitcoin-miner assumptions, compromised dependencies, social engineering, and any path requiring a privileged role.
- OUT OF SCOPE, reject on sight: pox.clar, pox-2.clar, pox-3.clar, pox_1/2/3.rs (superseded), README, tests, benches, config; the external sbtc-token except where pox-5's own use of it is the flaw; denial of service, gas griefing, unbounded loops and memory hygiene; secp256k1, Bitcoin-consensus or Clarity-VM-internal defects with no path through pox-5 or pox-locking; STX/BTC price assumptions; funds sent by mistake; best-practice notes; theoretical findings.
- The impact must be one of: Critical - theft or unbacked minting of locked STX or sBTC rewards, permanent freezing of staked STX or sBTC, unlocking value never locked, double-counting a commitment or reward; High - theft or permanent freezing of reserve or fees, temporary freezing of staked funds, signing weight or reward slots exceeding locked value, an unsigned stacking action.
- Focus on real impact: value locked/unlocked/paid that the contract did not validate, sats credited that were never locked on Bitcoin, or a reward or commitment counted twice.

## Validate
- Write the equality the question claims is broken between two named values BEFORE tracing any code.
- Trace the exact reachable path from the attacker's call and record every read and write of locked/unlocked `STXBalance`, `protocol-bond-memberships`, `staker-info`, the reward-per-token snapshots, `last-accounted-rewards-only`, `seen-outpoints`, the sBTC `as-contract?` allowance, and `signer-manager-call-active`.
- Evaluate both sides of the equality before and after. If they still match, output no vulnerability.
- Check whether `verify-not-prepare-phase`, `validate-no-reentrancy` / `signer-manager-call-active`, `check-pox-lock-period`, `verify-signer-key-grant`, the `<=` guards, `parse_pox_stake_result`, or the coordinator's cycle-start handlers already prevent the divergence.
- State what the attacker gains per transaction and whether it is repeatable.
- Require exact file/function support and a reproducible Rust or Clarity test on a local chainstate.

## Output
If valid, output exactly:

### Title
[Bug statement] - ([File: file_path])

### Summary
[2-3 sentences]

### Finding Description
[The broken equality, the code path, root cause, the attacker's exact call, exploit flow, and why existing guards fail]

### Impact Explanation
[What is stolen, minted, frozen, unlocked or double-counted, which party, repeatability, matching severity category]

### Likelihood Explanation
[Preconditions, cycle phase and membership state required, attacker cost, feasibility, repeatability]

### Recommendation
[Specific fix]

### Proof of Concept
[Rust or Clarity test plan with the exact assertions on both sides of the equality]

If invalid, output exactly:
#NoVulnerability found for this question.

No extra text.
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generate a strict bounty-style validation prompt for stacks-core stacking claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim.
- Check SECURITY.md and Researcher.Md for scope, exclusions, and valid impact classes.
- Do not create a new vulnerability if the submitted claim is weak or invalid.
- Do not upgrade severity unless the provided evidence proves the higher impact.
- A claim is only valid if the report states the broken equality between two named values and shows both sides concretely. Reject prose-only claims.
- Reject anything requiring the bond admin, pause admin, a miner, a signer with another's key, the SIP-031 recipient, another staker's key, a malicious peer/node/RPC/relayer/Bitcoin-miner, a compromised dependency, or social engineering.
- OUT OF SCOPE, reject on sight: pox.clar, pox-2.clar, pox-3.clar, pox_1/2/3.rs (superseded), README, tests, benches, config; the external sbtc-token except where pox-5's own use of it is the flaw; denial of service, gas griefing, unbounded loops and memory hygiene; secp256k1, Bitcoin-consensus or Clarity-VM-internal defects with no path through pox-5 or pox-locking; STX/BTC price assumptions; centralization risk; funds sent by mistake; best-practice notes; feature requests; theoretical findings.
- The impact must be one of: Critical - theft or unbacked minting of locked STX or sBTC rewards, permanent freezing of staked STX or sBTC, unlocking value never locked, double-counting a commitment or reward; High - theft or permanent freezing of reserve or fees, temporary freezing of staked funds, signing weight or reward slots exceeding locked value, an unsigned stacking action.
- Reject claims where the only loss is the attacker's own stake.
- Reject if the bug was already fixed, publicly disclosed, or covered by a known-issues list.
- A valid report must be triggerable by an unprivileged account against the current code with their own funds and their own contracts.
- A PoC is mandatory. Prefer #NoVulnerability over speculative reports.

## Required Validation Checks
All must pass:
1. Exact in-scope file, function/native/struct, and line references.
2. The equality written explicitly, with both sides shown before and after.
3. Clear root cause: which lock/commit mismatch, reward-settlement gap, L1-proof weakness, unlock error, reentrancy, or authorization gap causes it.
4. Reachable exploit path: preconditions -> attacker call -> pox-5, pox-locking and coordinator sequence -> observed divergence.
5. `verify-not-prepare-phase`, the reentrancy guard, `check-pox-lock-period`, `verify-signer-key-grant`, `parse_pox_stake_result` and the cycle-start handlers reviewed and shown insufficient.
6. Impact stated concretely: which funds, whose, and whether it is repeatable.
7. Reproducible proof: Rust or Clarity test on a local chainstate with the asserted values.

## Silent Triage Questions
Before output, internally answer:
- What exactly is the equality, and does it actually fail?
- Can an ordinary staker trigger it with no privileged role and no other user's key?
- Is the flaw in pox-5 / pox-locking / the coordinator, not in the external sbtc-token or Bitcoin?
- What value is stolen, minted, frozen, unlocked or double-counted, whose is it, and can it be repeated?
- Would an Immunefi triager accept the exploit path under the Blockchain/DLT severity system?
- What exact test would prove it?

## Output
If valid, output exactly:

Audit Report

## Title
[Clear vulnerability statement] - ([File: file_path])

## Summary
[2-3 sentence summary of the broken equality and impact]

## Finding Description
[Exact code path, the equality, root cause, exploit flow, and why existing guards fail]

## Impact Explanation
[What is stolen, minted, frozen, unlocked or double-counted, affected party, repeatability, severity category]

## Likelihood Explanation
[Attacker capability, preconditions, state required, cost, feasibility]

## Recommendation
[Specific fix guidance]

## Proof of Concept
[Minimal reproducible steps or Rust/Clarity test plan with concrete assertions]

If invalid, output exactly:
#NoVulnerability found for this question.

Output only one of the two outcomes above. No extra text.
"""
    return prompt


def scan_format(report: str) -> str:
    """
    Generate a short cross-project analog scan prompt for stacks-core stacking.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Rules
- Use in-scope repo context only (pox-5.clar, pox-4.clar, sip-031.clar, lockup.clar, `pox-locking/src/**`, boot/mod.rs, signer_set.rs, coordinator/mod.rs, accounts.rs, the burn stacking ops and signed_structured_data.rs, excluding superseded PoX versions). Do not ask for code or claim missing files.
- Use the external report only as a bug-class hint, not as proof.
- Keep only unprivileged-account analogs that break an equality: STX/sBTC locked or unlocked that the contract did not validate, sBTC rewards paid that were not earned or counted twice, sats credited by an L1 proof that were never locked on Bitcoin, value unlocked early or frozen forever, or a stacking action the staker/signer never authorised.
- OUT OF SCOPE, reject on sight: superseded PoX contracts, README, tests, benches, config; the external sbtc-token except where pox-5's own use of it is the flaw; denial of service, gas griefing, unbounded loops and memory hygiene; secp256k1, Bitcoin-consensus or Clarity-VM-internal defects with no path through pox-5 or pox-locking; anything requiring the bond/pause admin, a miner, another user's key; malicious peer/node assumptions; STX/BTC price assumptions; funds sent by mistake; best-practice notes; theoretical findings.
- The impact must be one of: Critical - theft or unbacked minting of locked STX or sBTC rewards, permanent freezing of staked STX or sBTC, unlocking value never locked, double-counting a commitment or reward; High - theft or permanent freezing of reserve or fees, temporary freezing of staked funds, signing weight or reward slots exceeding locked value, an unsigned stacking action.
- Reject analogs where the only loss is the attacker's own stake.

## Validate
- Map the bug class to the strongest reachable path in this repo and state the equality it would break.
- Evaluate both sides before and after the attacker's call sequence.
- Prove root cause with exact file/function support.
- Accept only concrete theft, unbacked minting, permanent or temporary freezing, unlocking value never locked, double-counting, or an unsigned stacking action.

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
