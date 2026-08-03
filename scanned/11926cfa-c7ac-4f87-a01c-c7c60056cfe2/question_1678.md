# Q1678: reserve-backed asset confusion via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control proofs, remote account mappings, and wrapped calls that end in asset movement so that `impl pallet_asset_conversion::Config` reaches a path where fee charging, asset conversion, and final settlement observe different balances or asset kinds, breaking the invariant that fees, refunds, and swapped amounts must reconcile with the final debits and credits, and leading to high - severe availability loss on a critical asset-transfer or xcm path?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_asset_conversion::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: proofs, remote account mappings, and wrapped calls that end in asset movement
- Exploit idea: reaches a path where fee charging, asset conversion, and final settlement observe different balances or asset kinds
- Invariant to test: fees, refunds, and swapped amounts must reconcile with the final debits and credits
- Expected Immunefi impact: High - severe availability loss on a critical asset-transfer or XCM path
- Fast validation: xcm-emulator test that drives the exact reserve, teleport, or exporter flow and asserts no value drift
