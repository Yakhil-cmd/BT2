# Q2835: approval-settlement split via assets transfer transfer approved on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot asset config and control combined fee-payment and asset-transfer flows that touch both local balances and asset balances so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` makes asset-fee charging and final credit resolution disagree about which asset or amount was paid, breaking the invariant that asset-based fee payment must not debit less value than the chain settles or executes against, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: combined fee-payment and asset-transfer flows that touch both local balances and asset balances
- Exploit idea: makes asset-fee charging and final credit resolution disagree about which asset or amount was paid
- Invariant to test: asset-based fee payment must not debit less value than the chain settles or executes against
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
