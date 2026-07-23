import json
import os

MAX_REPO = 25
SOURCE_REPO = 'kaiachain/kaia'
REPO_NAME = 'kaia'
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
    'accounts/accounts.go',
    'accounts/errors.go',
    'accounts/manager.go',
    'api/addrlock.go',
    'api/api_debug.go',
    'api/api_eth.go',
    'api/api_kaia.go',
    'api/api_kaia_account.go',
    'api/api_kaia_blockchain.go',
    'api/api_kaia_transaction.go',
    'api/api_net.go',
    'api/api_personal.go',
    'api/api_txpool.go',
    'api/backend.go',
    'api/tx_args.go',
    'blockchain/bad_blocks.go',
    'blockchain/blob_storage.go',
    'blockchain/block_validator.go',
    'blockchain/blockchain.go',
    'blockchain/error.go',
    'blockchain/evm.go',
    'blockchain/forkid/forkid.go',
    'blockchain/gaspool.go',
    'blockchain/genesis.go',
    'blockchain/genesis_alloc.go',
    'blockchain/headerchain.go',
    'blockchain/init_derive_sha.go',
    'blockchain/state/access_list.go',
    'blockchain/state/database.go',
    'blockchain/state/iterator.go',
    'blockchain/state/journal.go',
    'blockchain/state/state_object.go',
    'blockchain/state/state_object_encoder.go',
    'blockchain/state/statedb.go',
    'blockchain/state/sync.go',
    'blockchain/state/transient_storage.go',
    'blockchain/state_migration.go',
    'blockchain/state_prefetcher.go',
    'blockchain/state_processor.go',
    'blockchain/state_transition.go',
    'blockchain/system/addressbook_v2.go',
    'blockchain/system/auction.go',
    'blockchain/system/constant.go',
    'blockchain/system/kip113.go',
    'blockchain/system/multicall.go',
    'blockchain/system/permissionless.go',
    'blockchain/system/proxy.go',
    'blockchain/system/rebalance.go',
    'blockchain/system/registry.go',
    'blockchain/system/storage.go',
    'blockchain/system/util.go',
    'blockchain/tx_journal.go',
    'blockchain/tx_list.go',
    'blockchain/tx_pool.go',
    'blockchain/types.go',
    'blockchain/types/account/account.go',
    'blockchain/types/account/account_common.go',
    'blockchain/types/account/account_serializer.go',
    'blockchain/types/account/externally_owned_account.go',
    'blockchain/types/account/legacy_account.go',
    'blockchain/types/account/smart_contract_account.go',
    'blockchain/types/accountkey/account_key.go',
    'blockchain/types/accountkey/account_key_fail.go',
    'blockchain/types/accountkey/account_key_legacy.go',
    'blockchain/types/accountkey/account_key_nil.go',
    'blockchain/types/accountkey/account_key_public.go',
    'blockchain/types/accountkey/account_key_role_based.go',
    'blockchain/types/accountkey/account_key_serializer.go',
    'blockchain/types/accountkey/account_key_weighted_multi_sig.go',
    'blockchain/types/accountkey/public_key.go',
    'blockchain/types/anchoring_data.go',
    'blockchain/types/block.go',
    'blockchain/types/bloom.go',
    'blockchain/types/contract_ref.go',
    'blockchain/types/derive_sha.go',
    'blockchain/types/derivesha/concat.go',
    'blockchain/types/derivesha/mux.go',
    'blockchain/types/derivesha/orig.go',
    'blockchain/types/derivesha/simple.go',
    'blockchain/types/log.go',
    'blockchain/types/receipt.go',
    'blockchain/types/transaction.go',
    'blockchain/types/transaction_signing.go',
    'blockchain/types/tx_internal_data.go',
    'blockchain/types/tx_internal_data_account_creation.go',
    'blockchain/types/tx_internal_data_account_update.go',
    'blockchain/types/tx_internal_data_cancel.go',
    'blockchain/types/tx_internal_data_chain_data_anchoring.go',
    'blockchain/types/tx_internal_data_ethereum_access_list.go',
    'blockchain/types/tx_internal_data_ethereum_blob.go',
    'blockchain/types/tx_internal_data_ethereum_dynamic_fee.go',
    'blockchain/types/tx_internal_data_ethereum_set_code.go',
    'blockchain/types/tx_internal_data_fee_delegated_account_update.go',
    'blockchain/types/tx_internal_data_fee_delegated_account_update_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_cancel.go',
    'blockchain/types/tx_internal_data_fee_delegated_cancel_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_chain_data_anchoring.go',
    'blockchain/types/tx_internal_data_fee_delegated_chain_data_anchoring_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_smart_contract_deploy.go',
    'blockchain/types/tx_internal_data_fee_delegated_smart_contract_deploy_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_smart_contract_execution.go',
    'blockchain/types/tx_internal_data_fee_delegated_smart_contract_execution_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_value_transfer.go',
    'blockchain/types/tx_internal_data_fee_delegated_value_transfer_memo.go',
    'blockchain/types/tx_internal_data_fee_delegated_value_transfer_memo_with_ratio.go',
    'blockchain/types/tx_internal_data_fee_delegated_value_transfer_with_ratio.go',
    'blockchain/types/tx_internal_data_legacy.go',
    'blockchain/types/tx_internal_data_serializer.go',
    'blockchain/types/tx_internal_data_smart_contract_deploy.go',
    'blockchain/types/tx_internal_data_smart_contract_execution.go',
    'blockchain/types/tx_internal_data_value_transfer.go',
    'blockchain/types/tx_internal_data_value_transfer_memo.go',
    'blockchain/types/tx_signature.go',
    'blockchain/types/tx_signatures.go',
    'blockchain/vm/analysis.go',
    'blockchain/vm/common.go',
    'blockchain/vm/contract.go',
    'blockchain/vm/contracts.go',
    'blockchain/vm/eips.go',
    'blockchain/vm/errors.go',
    'blockchain/vm/evm.go',
    'blockchain/vm/gas.go',
    'blockchain/vm/gas_table.go',
    'blockchain/vm/instructions.go',
    'blockchain/vm/interface.go',
    'blockchain/vm/interpreter.go',
    'blockchain/vm/jump_table.go',
    'blockchain/vm/jumpdests.go',
    'blockchain/vm/memory.go',
    'blockchain/vm/memory_table.go',
    'blockchain/vm/opcodes.go',
    'blockchain/vm/operations_acl.go',
    'blockchain/vm/precompiles.go',
    'blockchain/vm/runtime/env.go',
    'blockchain/vm/runtime/runtime.go',
    'blockchain/vm/stack.go',
    'blockchain/vm/stack_table.go',
    'common/big.go',
    'common/bytes.go',
    'common/hexutil/hexutil.go',
    'common/hexutil/json.go',
    'common/math/big.go',
    'common/math/integer.go',
    'common/types.go',
    'consensus/bft/codec.go',
    'consensus/bft/messages.go',
    'consensus/consensus.go',
    'consensus/engine/engine.go',
    'consensus/engine/sealer.go',
    'consensus/errors.go',
    'consensus/executor.go',
    'consensus/faker/faker.go',
    'consensus/istanbul/backend.go',
    'consensus/istanbul/backend/api.go',
    'consensus/istanbul/backend/backend.go',
    'consensus/istanbul/backend/engine.go',
    'consensus/istanbul/backend/handler.go',
    'consensus/istanbul/backend/vrank.go',
    'consensus/istanbul/config.go',
    'consensus/istanbul/core/backlog.go',
    'consensus/istanbul/core/commit.go',
    'consensus/istanbul/core/core.go',
    'consensus/istanbul/core/errors.go',
    'consensus/istanbul/core/events.go',
    'consensus/istanbul/core/handler.go',
    'consensus/istanbul/core/message_set.go',
    'consensus/istanbul/core/prepare.go',
    'consensus/istanbul/core/preprepare.go',
    'consensus/istanbul/core/request.go',
    'consensus/istanbul/core/roundchange.go',
    'consensus/istanbul/core/roundstate.go',
    'consensus/istanbul/core/types.go',
    'consensus/istanbul/errors.go',
    'consensus/istanbul/events.go',
    'consensus/istanbul/sealer.go',
    'consensus/istanbul/utils.go',
    'consensus/protocol.go',
    'contracts/service_chain/IERC20BridgeReceiver.sol',
    'contracts/service_chain/IERC721BridgeReceiver.sol',
    'contracts/service_chain/bridge/Bridge.sol',
    'contracts/service_chain/bridge/BridgeCounterPart.sol',
    'contracts/service_chain/bridge/BridgeFee.sol',
    'contracts/service_chain/bridge/BridgeHandledRequests.sol',
    'contracts/service_chain/bridge/BridgeOperator.sol',
    'contracts/service_chain/bridge/BridgeTokens.sol',
    'contracts/service_chain/bridge/BridgeTransfer.sol',
    'contracts/service_chain/bridge/BridgeTransferERC20.sol',
    'contracts/service_chain/bridge/BridgeTransferERC721.sol',
    'contracts/service_chain/bridge/BridgeTransferKLAY.sol',
    'crypto/blake2b/blake2b.go',
    'crypto/blake2b/blake2bAVX2_amd64.go',
    'crypto/blake2b/blake2b_amd64.go',
    'crypto/blake2b/blake2b_generic.go',
    'crypto/blake2b/blake2b_ref.go',
    'crypto/blake2b/blake2x.go',
    'crypto/blake2b/register.go',
    'crypto/bls/bls.go',
    'crypto/bls/blst/aliases.go',
    'crypto/bls/blst/cache.go',
    'crypto/bls/blst/public_key.go',
    'crypto/bls/blst/secret_key.go',
    'crypto/bls/blst/signature.go',
    'crypto/bls/types/bls_types.go',
    'crypto/bn256/bn256_fast.go',
    'crypto/bn256/bn256_slow.go',
    'crypto/bn256/cloudflare/bn256.go',
    'crypto/bn256/cloudflare/constants.go',
    'crypto/bn256/cloudflare/curve.go',
    'crypto/bn256/cloudflare/gfp.go',
    'crypto/bn256/cloudflare/gfp12.go',
    'crypto/bn256/cloudflare/gfp2.go',
    'crypto/bn256/cloudflare/gfp6.go',
    'crypto/bn256/cloudflare/gfp_decl.go',
    'crypto/bn256/cloudflare/gfp_generic.go',
    'crypto/bn256/cloudflare/lattice.go',
    'crypto/bn256/cloudflare/optate.go',
    'crypto/bn256/cloudflare/twist.go',
    'crypto/bn256/gnark/g1.go',
    'crypto/bn256/gnark/g2.go',
    'crypto/bn256/gnark/gt.go',
    'crypto/bn256/gnark/pairing.go',
    'crypto/bn256/google/bn256.go',
    'crypto/bn256/google/constants.go',
    'crypto/bn256/google/curve.go',
    'crypto/bn256/google/gfp12.go',
    'crypto/bn256/google/gfp2.go',
    'crypto/bn256/google/gfp6.go',
    'crypto/bn256/google/optate.go',
    'crypto/bn256/google/twist.go',
    'crypto/crypto.go',
    'crypto/ecies/ecies.go',
    'crypto/ecies/params.go',
    'crypto/kzg4844/kzg4844.go',
    'crypto/kzg4844/kzg4844_ckzg_cgo.go',
    'crypto/kzg4844/kzg4844_ckzg_nocgo.go',
    'crypto/kzg4844/kzg4844_gokzg.go',
    'crypto/secp256k1/curve.go',
    'crypto/secp256k1/secp256.go',
    'crypto/secp256r1/verifier.go',
    'crypto/sha3/hashes.go',
    'crypto/sha3/keccakf.go',
    'crypto/sha3/keccakf_amd64.go',
    'crypto/sha3/register.go',
    'crypto/sha3/sha3.go',
    'crypto/sha3/shake.go',
    'crypto/sha3/xor.go',
    'crypto/sha3/xor_generic.go',
    'crypto/sha3/xor_unaligned.go',
    'crypto/signature_cgo.go',
    'crypto/signature_nocgo.go',
    'datasync/downloader/api_kaia_downloader.go',
    'datasync/downloader/api_kaia_downloader_sync.go',
    'datasync/downloader/downloader.go',
    'datasync/downloader/events.go',
    'datasync/downloader/modes.go',
    'datasync/downloader/peer.go',
    'datasync/downloader/queue.go',
    'datasync/downloader/resultstore.go',
    'datasync/downloader/statesync.go',
    'datasync/downloader/types.go',
    'datasync/fetcher/fetcher.go',
    'kaiax/auction/bid.go',
    'kaiax/auction/config.go',
    'kaiax/auction/eip712.go',
    'kaiax/auction/errors.go',
    'kaiax/auction/impl/api.go',
    'kaiax/auction/impl/bid_pool.go',
    'kaiax/auction/impl/builder.go',
    'kaiax/auction/impl/execution.go',
    'kaiax/auction/impl/getter.go',
    'kaiax/auction/impl/handler.go',
    'kaiax/auction/impl/init.go',
    'kaiax/auction/impl/metric.go',
    'kaiax/auction/interface.go',
    'kaiax/gasless/config.go',
    'kaiax/gasless/impl/api.go',
    'kaiax/gasless/impl/builder.go',
    'kaiax/gasless/impl/constant.go',
    'kaiax/gasless/impl/errors.go',
    'kaiax/gasless/impl/execution.go',
    'kaiax/gasless/impl/getter.go',
    'kaiax/gasless/impl/init.go',
    'kaiax/gasless/impl/tx_counter.go',
    'kaiax/gasless/impl/tx_pool.go',
    'kaiax/gasless/interface.go',
    'kaiax/gov/contractgov/impl/api.go',
    'kaiax/gov/contractgov/impl/error.go',
    'kaiax/gov/contractgov/impl/getter.go',
    'kaiax/gov/contractgov/impl/init.go',
    'kaiax/gov/contractgov/interface.go',
    'kaiax/gov/error.go',
    'kaiax/gov/headergov/error.go',
    'kaiax/gov/headergov/gov.go',
    'kaiax/gov/headergov/history.go',
    'kaiax/gov/headergov/impl/api.go',
    'kaiax/gov/headergov/impl/error.go',
    'kaiax/gov/headergov/impl/execution.go',
    'kaiax/gov/headergov/impl/getter.go',
    'kaiax/gov/headergov/impl/header.go',
    'kaiax/gov/headergov/impl/init.go',
    'kaiax/gov/headergov/impl/rewind.go',
    'kaiax/gov/headergov/impl/schema.go',
    'kaiax/gov/headergov/interface.go',
    'kaiax/gov/headergov/vote.go',
    'kaiax/gov/impl/api.go',
    'kaiax/gov/impl/execution.go',
    'kaiax/gov/impl/getter.go',
    'kaiax/gov/impl/header.go',
    'kaiax/gov/impl/init.go',
    'kaiax/gov/impl/rewind.go',
    'kaiax/gov/interface.go',
    'kaiax/gov/param.go',
    'kaiax/gov/paramset.go',
    'kaiax/interface.go',
    'kaiax/randao/errors.go',
    'kaiax/randao/impl/api.go',
    'kaiax/randao/impl/execution.go',
    'kaiax/randao/impl/getter.go',
    'kaiax/randao/impl/header.go',
    'kaiax/randao/impl/init.go',
    'kaiax/randao/interface.go',
    'kaiax/reward/config.go',
    'kaiax/reward/errors.go',
    'kaiax/reward/impl/api.go',
    'kaiax/reward/impl/blockstate.go',
    'kaiax/reward/impl/execution.go',
    'kaiax/reward/impl/getter.go',
    'kaiax/reward/impl/header.go',
    'kaiax/reward/impl/init.go',
    'kaiax/reward/interface.go',
    'kaiax/reward/spec.go',
    'kaiax/staking/errors.go',
    'kaiax/staking/impl/api.go',
    'kaiax/staking/impl/execution.go',
    'kaiax/staking/impl/getter.go',
    'kaiax/staking/impl/init.go',
    'kaiax/staking/impl/preload_buffer.go',
    'kaiax/staking/impl/schema.go',
    'kaiax/staking/interface.go',
    'kaiax/staking/p2p_staking_info.go',
    'kaiax/staking/staking_info.go',
    'kaiax/supply/errors.go',
    'kaiax/supply/impl/api.go',
    'kaiax/supply/impl/execution.go',
    'kaiax/supply/impl/getter.go',
    'kaiax/supply/impl/init.go',
    'kaiax/supply/impl/schema.go',
    'kaiax/supply/interface.go',
    'kaiax/supply/total_supply.go',
    'kaiax/system/impl/blockstate.go',
    'kaiax/system/impl/init.go',
    'kaiax/system/interface.go',
    'kaiax/valset/address_set.go',
    'kaiax/valset/impl/api.go',
    'kaiax/valset/impl/blockstate.go',
    'kaiax/valset/impl/consensus.go',
    'kaiax/valset/impl/error.go',
    'kaiax/valset/impl/execution.go',
    'kaiax/valset/impl/getter.go',
    'kaiax/valset/impl/getter_context.go',
    'kaiax/valset/impl/getter_council.go',
    'kaiax/valset/impl/getter_demote.go',
    'kaiax/valset/impl/getter_permissionless.go',
    'kaiax/valset/impl/getter_proposers.go',
    'kaiax/valset/impl/init.go',
    'kaiax/valset/impl/schema.go',
    'kaiax/valset/impl/transition.go',
    'kaiax/valset/impl/transition_context.go',
    'kaiax/valset/interface.go',
    'kaiax/valset/types.go',
    'kaiax/vrank/collector.go',
    'kaiax/vrank/errors.go',
    'kaiax/vrank/impl/api.go',
    'kaiax/vrank/impl/consensus.go',
    'kaiax/vrank/impl/execution.go',
    'kaiax/vrank/impl/getter.go',
    'kaiax/vrank/impl/handler.go',
    'kaiax/vrank/impl/init.go',
    'kaiax/vrank/impl/rewind.go',
    'kaiax/vrank/impl/schema.go',
    'kaiax/vrank/impl/scoring.go',
    'kaiax/vrank/interface.go',
    'kaiax/vrank/types.go',
    'networks/grpc/gServer.go',
    'networks/p2p/dialsched.go',
    'networks/p2p/dialsched_util.go',
    'networks/p2p/discover/database.go',
    'networks/p2p/discover/discovery.go',
    'networks/p2p/discover/discovery_api.go',
    'networks/p2p/discover/metrics.go',
    'networks/p2p/discover/node.go',
    'networks/p2p/discover/ntp.go',
    'networks/p2p/discover/ratelimit.go',
    'networks/p2p/discover/table_bond.go',
    'networks/p2p/discover/table_data.go',
    'networks/p2p/discover/table_init.go',
    'networks/p2p/discover/table_lookup.go',
    'networks/p2p/discover/table_storage.go',
    'networks/p2p/discover/udp.go',
    'networks/p2p/discover/utils.go',
    'networks/p2p/message.go',
    'networks/p2p/metrics.go',
    'networks/p2p/msgrate/msgrate.go',
    'networks/p2p/netutil/error.go',
    'networks/p2p/netutil/net.go',
    'networks/p2p/netutil/toobig_notwindows.go',
    'networks/p2p/netutil/toobig_windows.go',
    'networks/p2p/peer.go',
    'networks/p2p/peer_error.go',
    'networks/p2p/protocol.go',
    'networks/p2p/rlpx/buffer.go',
    'networks/p2p/rlpx/rlpx.go',
    'networks/p2p/server.go',
    'networks/p2p/server_base.go',
    'networks/p2p/server_multi.go',
    'networks/p2p/server_util.go',
    'networks/p2p/tracker/tracker.go',
    'networks/p2p/transport.go',
    'networks/p2p/util.go',
    'networks/rpc/client.go',
    'networks/rpc/endpoints.go',
    'networks/rpc/errors.go',
    'networks/rpc/handler.go',
    'networks/rpc/http.go',
    'networks/rpc/inproc.go',
    'networks/rpc/ipc.go',
    'networks/rpc/ipc_unix.go',
    'networks/rpc/ipc_windows.go',
    'networks/rpc/json.go',
    'networks/rpc/server.go',
    'networks/rpc/service.go',
    'networks/rpc/stdio.go',
    'networks/rpc/subscription.go',
    'networks/rpc/types.go',
    'networks/rpc/websocket.go',
    'node/api_admin.go',
    'node/api_admin_network.go',
    'node/api_debug.go',
    'node/api_kaia.go',
    'node/cn/api_admin_chain.go',
    'node/cn/api_backend.go',
    'node/cn/api_debug.go',
    'node/cn/api_debug_storage.go',
    'node/cn/api_kaia.go',
    'node/cn/backend.go',
    'node/cn/bloombits.go',
    'node/cn/channel_manager.go',
    'node/cn/cnpeers.go',
    'node/cn/config.go',
    'node/cn/filters/api_kaia_filter.go',
    'node/cn/filters/filter.go',
    'node/cn/filters/filter_system.go',
    'node/cn/gasprice/feehistory.go',
    'node/cn/gasprice/gasprice.go',
    'node/cn/handler.go',
    'node/cn/known_hash_set.go',
    'node/cn/peer.go',
    'node/cn/peer_set.go',
    'node/cn/protocol.go',
    'node/cn/snap/handler.go',
    'node/cn/snap/nodeset.go',
    'node/cn/snap/peer.go',
    'node/cn/snap/protocol.go',
    'node/cn/snap/range.go',
    'node/cn/snap/sync.go',
    'node/cn/snap/tracker.go',
    'node/cn/state_accessor.go',
    'node/cn/sync.go',
    'node/config.go',
    'node/errors.go',
    'node/node.go',
    'node/sc/api_bridge.go',
    'node/sc/bridge_accounts.go',
    'node/sc/bridge_addr_journal.go',
    'node/sc/bridge_manager.go',
    'node/sc/bridgepeer.go',
    'node/sc/bridgepool/bridge_tx_journal.go',
    'node/sc/bridgepool/bridge_tx_pool.go',
    'node/sc/bridgepool/sorted_map_list.go',
    'node/sc/event_interface.go',
    'node/sc/event_parse.go',
    'node/sc/local_backend.go',
    'node/sc/main_bridge_handler.go',
    'node/sc/main_event_handler.go',
    'node/sc/mainbridge.go',
    'node/sc/protocol.go',
    'node/sc/remote_backend.go',
    'node/sc/sub_bridge_handler.go',
    'node/sc/sub_event_handler.go',
    'node/sc/subbridge.go',
    'node/sc/vt_recovery.go',
    'node/service.go',
    'params/blob_config.go',
    'params/computation_cost_params.go',
    'params/config.go',
    'params/denomination.go',
    'params/governance_params.go',
    'params/kip71_config.go',
    'params/network_params.go',
    'params/protocol_params.go',
    'rlp/decode.go',
    'rlp/encbuffer.go',
    'rlp/encode.go',
    'rlp/internal/rlpstruct/rlpstruct.go',
    'rlp/iterator.go',
    'rlp/raw.go',
    'rlp/safe.go',
    'rlp/typecache.go',
    'rlp/unsafe.go',
    'snapshot/conversion.go',
    'snapshot/difflayer.go',
    'snapshot/disklayer.go',
    'snapshot/generate.go',
    'snapshot/iterator.go',
    'snapshot/iterator_binary.go',
    'snapshot/iterator_fast.go',
    'snapshot/journal.go',
    'snapshot/snapshot.go',
    'snapshot/sort.go',
    'snapshot/wipe.go',
    'storage/database/badger_database.go',
    'storage/database/batch.go',
    'storage/database/cache_manager.go',
    'storage/database/db_manager.go',
    'storage/database/db_migration.go',
    'storage/database/dynamodb.go',
    'storage/database/dynamodb_readonly.go',
    'storage/database/filedb.go',
    'storage/database/interface.go',
    'storage/database/iterator.go',
    'storage/database/leveldb_database.go',
    'storage/database/memory_database.go',
    'storage/database/metrics.go',
    'storage/database/pebbledb_database.go',
    'storage/database/rocksdb_database.go',
    'storage/database/rocksdb_database_config.go',
    'storage/database/rocksdb_database_nobuild.go',
    'storage/database/s3filedb.go',
    'storage/database/schema.go',
    'storage/database/sharded_database.go',
    'storage/statedb/cache.go',
    'storage/statedb/cache_fastcache.go',
    'storage/statedb/cache_hybrid.go',
    'storage/statedb/cache_redis.go',
    'storage/statedb/database.go',
    'storage/statedb/encoding.go',
    'storage/statedb/errors.go',
    'storage/statedb/flat_trie.go',
    'storage/statedb/hasher.go',
    'storage/statedb/iterator.go',
    'storage/statedb/node.go',
    'storage/statedb/node_enc.go',
    'storage/statedb/proof.go',
    'storage/statedb/secure_trie.go',
    'storage/statedb/stacktrie.go',
    'storage/statedb/sync.go',
    'storage/statedb/sync_bloom.go',
    'storage/statedb/trie.go',
    'work/builder/builder.go',
    'work/builder/bundle.go',
    'work/builder/tx_or_gen.go',
    'work/execution.go',
    'work/work.go',
    'work/worker.go',
]

target_scopes = [
    'Critical. A remote transaction, fee-delegation, account-key, or authorization bug executes without the required signature or role, stealing KAIA/tokens or spending another account nonce.',
    'Critical. A block, proof, snapshot, trie, or sync input is accepted despite violating Kaia state-transition or consensus rules, causing invalid balances, double-spend, or chain split on honest nodes.',
    'Critical. A service-chain bridge, system-contract, or cross-module execution flaw lets an attacker mint, unlock, withdraw, or redirect KAIA, ERC20, ERC721, or reward assets without required authority.',
    'High. A governance, validator-set, staking, reward, randao, header-gov, or auction boundary bypass grants unauthorized chain privileges or reroutes treasury, validator, or block-reward value.',
    'High. A public RPC, P2P, txpool, gasless, or bridge-message path bypasses intended auth, replay, nonce, or domain-separation checks and causes unauthorized execution, censorship, or durable state corruption.',
    'Medium. An honest-but-permitted operation within configured limits misprices fees, rewards, snapshots, or persisted state and locks funds or breaks core chain functionality above material thresholds.',
]

KAIA_ALLOWED_IMPACT_SCOPE = '## Kaia Allowed Impact Gate\nOnly accept repository-native impacts:\n- Unauthorized transfer, mint, unlock, burn, fee charge, reward distribution, or key/nonce consumption affecting KAIA, bridged assets, or system-managed funds.\n- Invalid state transition, invalid block/proof/snapshot acceptance, or consensus divergence on honest nodes.\n- Bridge, governance, validator, or system-contract privilege escalation that changes protected chain state or asset ownership.\n- Persistent corruption of trie/state/snapshot data that breaks canonical execution, withdrawals, transfers, or settlement.\nOut of scope: tests, mocks, generated bindings, local tooling, packaging, docs-only issues, logging/metrics, operator misconfiguration, compromised keys, majority-validator collusion, external service compromise, cryptographic primitive breaks without repository misuse, and gas-only or crash-only issues with no protected-state impact.'

KAIA_AUDIT_PIVOTS = '## Smart Audit Pivots\n- Transaction/state path: tx decoding, fee delegation, account-key checks, gas validation, nonce handling, state transition, precompile behavior, and receipt/state-root derivation.\n- Consensus/sync path: block/header validation, downloader/fetcher/snapshot/trie/proof import, persistence, and fork-choice invariants.\n- Privileged module path: `kaiax/*`, system contracts, staking, reward, valset, randao, governance, and header-gov must preserve authority, activation, and accounting boundaries.\n- Bridge/network path: service-chain bridge requests, replay protection, counterpart authentication, RPC namespaces, P2P messages, txpool/worker integration, and public debug/admin surfaces.'


def question_generator(target_file: str) -> str:
    """
    Generate focused Kaia exploit questions for one in-scope target.
    """

    prompt = f"""
    Generate Kaia security questions for this exact target:

    {target_file}

    Project lens:
    Focus on state transition, consensus acceptance, signature/account-key validation, fee delegation, bridge accounting, governance authority, validator/reward state, sync/snapshot import, and public RPC/P2P boundaries.

    Impact gate:
    {KAIA_ALLOWED_IMPACT_SCOPE}

    {KAIA_AUDIT_PIVOTS}

    Rules:
    * Treat `File Name:` as the exact file and `Scope:` as the only impact.
    * Assume repo context is accessible; do not ask for code.
    * Attacker is remote and unprivileged unless the file exposes a narrower semi-trusted boundary: RPC caller, tx sender, fee payer, contract caller, P2P peer, sync peer, bridge participant, or permissionless governance trigger.
    * Local node operator, privileged governance keys, external services, and compromised private keys are trusted unless the question proves a public bypass in scoped code.
    * Do not rely on majority-validator collusion, malformed cryptographic primitives, or non-standard token behavior unless Kaia code misuses them.
    * Exclude tests, mocks, generated bindings, local tooling, packaging, docs-only issues, logging/metrics issues, gas-only DoS, crashes, style, and dependency-only behavior.
    * Generate 10 to 30 high-signal questions. Avoid generic checklist items and repeated root causes.
    * Name the exact value at risk: balance, nonce, account key, validator set, voting power, reward amount, bridge nonce, trie node, snapshot chunk, state root, receipt field, txpool entry, or protected storage slot.
    * Every question must be testable with a Foundry unit, integration, fork, or property test.

    Each question must include target symbol, attacker-controlled input, required state, call path, invariant, corrupted value, scoped impact, and proof idea.

    Output only valid Python. No markdown. No explanations.

    questions = [
    "[File: {target_file}] [Symbol: symbol_or_module] Can attacker-controlled INPUT under REQUIRED_STATE reach CALL_PATH and violate AUTH_OR_STATE_INVARIANT, corrupting EXACT_BALANCE_NONCE_ROOT_VALIDATOR_OR_BRIDGE_VALUE with scoped impact SCOPE_IMPACT? Proof idea: build a reproducible unit, integration, fork, or property test around the failing boundary.",
    ]
    """
    return prompt


def audit_format(question: str) -> str:
    """
    Generate a focused Kaia exploit-question validation prompt.
    """
    return f"""# KAIA EXPLOIT QUESTION REVIEW

## Exploit Question
{question}

## Scope Rules
- Audit only Kaia production code in this repository.
- Ignore tests, mocks, generated bindings, local tooling, packaging, and docs-only issues with no code-level impact.
- Do not ask for repo contents or claim files are missing.

## Objective
Decide whether the question leads to a real Kaia vulnerability. The attacker must enter through public RPC, transaction, contract, bridge, P2P, sync, snapshot, or permissionless governance-trigger flows available in scoped code.

Reject claims needing local operator control, privileged governance keys, majority-validator collusion, compromised keys, external service compromise, or cryptographic breaks without repository misuse. Prefer #NoVulnerability unless the path proves unauthorized asset movement, invalid state acceptance, privilege escalation over protected chain state, consensus divergence, or durable loss of core chain functionality.

## Required Impacts
{KAIA_ALLOWED_IMPACT_SCOPE}

{KAIA_AUDIT_PIVOTS}

## Method
1. Trace the public or semi-trusted entrypoint.
2. Map it to exact scoped files and functions.
3. Check auth boundary -> input validation -> persisted state -> downstream execution, consensus, bridge, or sync effect.
4. Identify the exact corrupted value and who loses funds, authority, or chain functionality.
5. Reject if existing guards preserve the invariant or impact is below contest thresholds.

## Reject Immediately
- Trusted operator, validator-majority, governance-admin, or key-compromise assumptions without a public bypass.
- External database, bridge relayer, oracle, or service compromise unless Kaia code fails to authenticate it.
- Harmless view-only mismatches, logging/metrics issues, gas-only DoS, crashes, unbounded growth, or dependency-only behavior.
- Tests, mocks, scripts, deployments, generated artifacts, packaging, local tooling, or docs-only issues with no code-level impact.

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
    Generate a cross-project analog scan prompt for Kaia issues.
    """
    prompt = f"""# ANALOG SCAN PROMPT

## External Report
{report}

## Task
Use the external report only as a bug-class seed. Search Kaia transaction, consensus, sync, bridge, governance, validator, reward, and public network/API code for a native analog with protected-state or asset impact.

## Required Impacts
{KAIA_ALLOWED_IMPACT_SCOPE}

{KAIA_AUDIT_PIVOTS}

Report only if this repository has its own reachable root cause, unprivileged or valid semi-trusted trigger, broken invariant, exact corrupted value, and matching target scope or allowed impact. Reject privileged operations, operator-only assumptions, majority-validator collusion, external-service compromise, resource-only issues, dependency-only behavior, and anything outside the production attack surface.

## Work Plan
1. Classify the external bug into one Kaia invariant.
2. Map it to exact scoped files/functions.
3. Trace attacker input through production validation and state updates.
4. Identify the wrong balance, nonce, key, validator set entry, vote weight, reward amount, bridge nonce, trie node, snapshot chunk, state root, receipt field, or protected storage value.
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
    Generate a strict Kaia validation prompt for security claims.
    """
    prompt = f"""# VALIDATION PROMPT

## Security Claim
{report}

## Rules
- Validate only the submitted claim against Kaia production code in this repository.
- Do not invent a stronger claim, change target scope, or upgrade severity without evidence.
- A valid issue must be triggered by an unprivileged or properly bounded semi-trusted actor exposed in scoped code: RPC caller, tx sender, fee payer, contract caller, P2P peer, sync peer, bridge participant, or permissionless governance trigger.
- Local operator controls, privileged governance keys, majority-validator collusion, compromised keys, and external services are trusted unless the claim proves a public bypass in repository code.
- Reject operator misconfiguration, pure cryptographic-break assumptions, gas-only DoS, crashes, unbounded growth, logs, style, dependency-only bugs, tests, mocks, scripts, deployments, generated artifacts, packaging, local tooling, and docs-only issues with no code-level impact.
- The final impact must match one `target_scopes` item or allowed impact below, identify the exact corrupted value, and meet Sherlock contest thresholds.

## Required Impacts
{KAIA_ALLOWED_IMPACT_SCOPE}

{KAIA_AUDIT_PIVOTS}

## Required Checks
1. Exact file/function references in scoped code.
2. Clear broken Kaia invariant tied to funds, protected chain state, consensus correctness, bridge accounting, governance authority, or validator/reward integrity.
3. Reachable exploit path: preconditions -> attacker input -> production call path -> bad value.
4. Existing guards reviewed and shown insufficient.
5. Exact wrong value named: balance, nonce, account key, storage slot, receipt field, state root, validator set entry, voting power, reward amount, bridge nonce, trie node, snapshot chunk, txpool entry, or protected config value.
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
