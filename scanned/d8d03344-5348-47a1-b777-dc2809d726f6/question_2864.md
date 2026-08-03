# Q2864: asset-fee mismatch via assettxpayment signed fee paying on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `AssetTxPayment` signed fee-paying path on People Polkadot asset config and control approval-based asset movement combined with fee payment in the same call bundle so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `AssetTxPayment` signed fee-paying path
- Attacker controls: approval-based asset movement combined with fee payment in the same call bundle
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers
