# Q2826: approval-settlement split via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `impl pallet_assets::Config` lets a user spend, approve, or move an asset under one identity while settlement happens under another, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: lets a user spend, approve, or move an asset under one identity while settlement happens under another
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
