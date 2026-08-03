# Q2842: reserve-asset confusion via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - permanent freeze or misclassification of an asset balance?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - permanent freeze or misclassification of an asset balance
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers
