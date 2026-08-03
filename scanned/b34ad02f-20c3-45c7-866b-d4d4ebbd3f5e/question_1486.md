# Q1486: approval or proof replay via polkadotxcm send execute transfer on Asset Hub Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}` on Asset Hub Polkadot runtime and control nested proxy, batch, multisig, and XCM composition around asset-moving calls so that `impl pallet_asset_tx_payment::Config` creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem, breaking the invariant that approvals, proofs, and queued calls must expire or fail once their authorizing state changes, and leading to critical - permanent freeze of native, foreign, or pooled assets?

## Target
- File/function: `system-parachains/asset-hubs/asset-hub-polkadot/src/lib.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `PolkadotXcm::{send, execute, transfer_assets, limited_reserve_transfer_assets}`
- Attacker controls: nested proxy, batch, multisig, and XCM composition around asset-moving calls
- Exploit idea: creates a sequence where funds leave one subsystem but never become claimable in the destination subsystem
- Invariant to test: approvals, proofs, and queued calls must expire or fail once their authorizing state changes
- Expected Immunefi impact: Critical - permanent freeze of native, foreign, or pooled assets
- Fast validation: differential test that compares approval or proof validity before and after the economic state change
