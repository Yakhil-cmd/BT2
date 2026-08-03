# Q1699: proxy-batched asset escape via nominationpools join bond extra on Asset Hub Kusama runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Asset Hub Kusama runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `impl pallet_asset_conversion::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that no user-controlled asset path may create unbacked issuance or release more value than it debits, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-kusama/src/lib.rs` :: `impl pallet_asset_conversion::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: no user-controlled asset path may create unbacked issuance or release more value than it debits
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: differential test that compares approval or proof validity before and after the economic state change
