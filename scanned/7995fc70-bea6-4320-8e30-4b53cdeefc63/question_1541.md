# Q1541: migration-balance drift via pallet remote proxy remote on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` reuses an approval, proof, or queued call after the economic precondition that justified it has changed, breaking the invariant that approvals, proofs, and queued calls must expire or fail once their authorizing state changes, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `pallet_remote_proxy::{remote_proxy, remote_proxy_with_registered_proof}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: reuses an approval, proof, or queued call after the economic precondition that justified it has changed
- Invariant to test: approvals, proofs, and queued calls must expire or fail once their authorizing state changes
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: differential test that compares approval or proof validity before and after the economic state change
