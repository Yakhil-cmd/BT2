# Q2877: approval-settlement split via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `impl pallet_asset_tx_payment::Config` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_asset_tx_payment::Config`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
