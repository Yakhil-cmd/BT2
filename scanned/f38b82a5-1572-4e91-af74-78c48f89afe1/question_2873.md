# Q2873: asset-fee mismatch via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `impl pallet_assets::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers
