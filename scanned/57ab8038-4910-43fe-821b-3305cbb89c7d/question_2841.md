# Q2841: approval-settlement split via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
