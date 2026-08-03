# Q2843: asset-fee mismatch via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `impl pallet_assets::Config` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
