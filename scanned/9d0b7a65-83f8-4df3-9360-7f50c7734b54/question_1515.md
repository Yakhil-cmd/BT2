# Q1515: proxy-batched asset escape via poolassets transfer transfer keep on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `PoolAssets::{transfer, transfer_keep_alive}` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` reaches a path where fee charging, asset conversion, and final settlement observe different balances or asset kinds, breaking the invariant that asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM, and leading to critical - direct loss of funds or unbacked asset issuance?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PoolAssets::{transfer, transfer_keep_alive}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: reaches a path where fee charging, asset conversion, and final settlement observe different balances or asset kinds
- Invariant to test: asset identity must stay stable across Assets, ForeignAssets, PoolAssets, AssetConversion, and XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset issuance
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
