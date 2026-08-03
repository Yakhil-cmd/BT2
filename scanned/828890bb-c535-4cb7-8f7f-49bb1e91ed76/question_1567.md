# Q1567: swap-settlement mismatch via nominationpools join bond extra on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}` causes an asset move or swap path to settle with a different asset identity than the accounting path expects, breaking the invariant that fees, refunds, and swapped amounts must reconcile with the final debits and credits, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Assets, ForeignAssets, PoolAssets, AssetConversion, AhOps, RemoteProxy, PolkadotXcm, NominationPools, Staking}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: causes an asset move or swap path to settle with a different asset identity than the accounting path expects
- Invariant to test: fees, refunds, and swapped amounts must reconcile with the final debits and credits
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
