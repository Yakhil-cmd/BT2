# Q2836: reserve-asset confusion via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
