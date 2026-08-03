# Q2870: asset-fee mismatch via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `impl pallet_assets::Config` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
