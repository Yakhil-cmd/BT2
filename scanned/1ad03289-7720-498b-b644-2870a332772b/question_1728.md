# Q1728: fee-conversion inconsistency via poolassets transfer transfer keep on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `PoolAssets::{transfer, transfer_keep_alive}` on Asset Hub Kusama runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that fees, refunds, and swapped amounts must reconcile with the final debits and credits, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `PoolAssets::{transfer, transfer_keep_alive}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: fees, refunds, and swapped amounts must reconcile with the final debits and credits
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: differential test that compares approval or proof validity before and after the economic state change
