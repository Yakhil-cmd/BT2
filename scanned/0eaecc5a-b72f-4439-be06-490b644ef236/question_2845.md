# Q2845: reserve-asset confusion via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `impl pallet_assets::Config` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
