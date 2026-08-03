# Q2863: reserve-asset confusion via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: causes `HollarFromHydration`, asset conversion, and transfer logic to classify the same asset differently across the path
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: stateful fuzz test over asset id, approval, and fee-asset combinations
