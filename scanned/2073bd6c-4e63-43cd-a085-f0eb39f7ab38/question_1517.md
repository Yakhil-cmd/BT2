# Q1517: migration-balance drift via pallet remote proxy remote on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}` on Asset Hub Polkadot runtime and control unlock, unbond, or claim timing around pool, staking, and migrated balances so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` reuses an approval, proof, or queued call after the economic precondition that justified it has changed, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}`
- Attacker controls: unlock, unbond, or claim timing around pool, staking, and migrated balances
- Exploit idea: reuses an approval, proof, or queued call after the economic precondition that justified it has changed
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
