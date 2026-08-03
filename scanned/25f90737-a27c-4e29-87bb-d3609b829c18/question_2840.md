# Q2840: asset-fee mismatch via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: asset ids, transaction-fee asset selection, and HOLLAR-like reserve paths controlled by the user
- Exploit idea: causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
