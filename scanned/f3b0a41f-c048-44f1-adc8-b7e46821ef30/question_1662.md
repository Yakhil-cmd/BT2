# Q1662: reserve-backed asset confusion via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection so that `impl pallet_asset_tx_payment::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that approvals, proofs, and queued calls must expire or fail once their authorizing state changes, and leading to critical - unauthorized withdrawal, unlock, or treasury-affecting transfer?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: liquidity ratios, exact-in/exact-out swap parameters, and fee-paying asset selection
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: approvals, proofs, and queued calls must expire or fail once their authorizing state changes
- Expected Immunefi impact: Critical - unauthorized withdrawal, unlock, or treasury-affecting transfer
- Fast validation: runtime integration test that compares debit, credit, issuance, and beneficiary state across all touched pallets
