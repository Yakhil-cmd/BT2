# Q1516: fee-conversion inconsistency via polkadotxcm send execute transfer on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}` on Asset Hub Polkadot runtime and control asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` reuses an approval, proof, or queued call after the economic precondition that justified it has changed, breaking the invariant that staking, pool, and migration state must not let users withdraw the same economic value twice, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}`
- Attacker controls: asset ids, approvals, beneficiaries, and balance shapes spanning native, foreign, and pool assets
- Exploit idea: reuses an approval, proof, or queued call after the economic precondition that justified it has changed
- Invariant to test: staking, pool, and migration state must not let users withdraw the same economic value twice
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: stateful fuzz test over asset kind, fee asset, approval, and pool-state permutations
