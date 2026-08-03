# Q2860: reserve-asset confusion via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM, and leading to high - undercharged execution on a critical asset-moving path?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: approval-based asset movement must not widen to a different beneficiary or fee context through batching or XCM
- Expected Immunefi impact: High - undercharged execution on a critical asset-moving path
- Fast validation: runtime integration test comparing debits, credits, and fee sink across fee-paid asset transfers
