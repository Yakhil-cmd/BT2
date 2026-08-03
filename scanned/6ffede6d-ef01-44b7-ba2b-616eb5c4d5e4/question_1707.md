# Q1707: proxy-batched asset escape via poolassets transfer transfer keep on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `PoolAssets::{transfer, transfer_keep_alive}` on Asset Hub Kusama runtime and control proofs, remote account mappings, and wrapped calls that end in asset movement so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}` makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PoolAssets::{transfer, transfer_keep_alive}`
- Attacker controls: proofs, remote account mappings, and wrapped calls that end in asset movement
- Exploit idea: makes proxy, XCM, or batched execution bypass the intended restrictions of the underlying asset or staking path
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
