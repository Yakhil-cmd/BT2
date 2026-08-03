# Q2847: approval-settlement split via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `impl pallet_assets::Config` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `impl pallet_assets::Config`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers
