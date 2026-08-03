# Q1666: approval or proof replay via polkadotxcm send execute transfer on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}` on Asset Hub Kusama runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}` causes an asset move or swap path to settle with a different asset identity than the accounting path expects, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: causes an asset move or swap path to settle with a different asset identity than the accounting path expects
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
