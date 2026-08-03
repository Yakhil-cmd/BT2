# Q2850: approval-settlement split via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `impl pallet_assets::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
