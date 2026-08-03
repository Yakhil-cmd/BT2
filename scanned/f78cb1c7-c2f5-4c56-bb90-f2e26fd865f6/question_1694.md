# Q1694: reserve-backed asset confusion via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets so that `impl pallet_assets::Config` causes an asset move or swap path to settle with a different asset identity than the accounting path expects, breaking the invariant that batching and proxying must not widen permissions on asset movement or treasury-affecting flows, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_assets::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: XCM messages that mix reserve-backed assets, foreign assets, and local trust-backed assets
- Exploit idea: causes an asset move or swap path to settle with a different asset identity than the accounting path expects
- Invariant to test: batching and proxying must not widen permissions on asset movement or treasury-affecting flows
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
