# Q2839: reserve-asset confusion via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
