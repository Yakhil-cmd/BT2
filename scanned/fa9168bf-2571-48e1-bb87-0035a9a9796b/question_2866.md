# Q2866: reserve-asset confusion via polkadotxcm send transfer assets on People Polkadot asset config

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path on People Polkadot asset config and control XCM asset movements where reserve matching and local asset ownership can disagree so that `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot` creates a path where the fee sink and the value-moving path observe different post-state balances, breaking the invariant that reserve-matched foreign assets must not be spendable as if they were a different local asset class, and leading to critical - direct loss of funds or unbacked asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/assets.rs` :: `hollar::HollarFromHydration / HollarLocation / CreditToStakingPot`
- Entrypoint: `PolkadotXcm::{send, transfer_assets}` using the HOLLAR-like asset path
- Attacker controls: XCM asset movements where reserve matching and local asset ownership can disagree
- Exploit idea: creates a path where the fee sink and the value-moving path observe different post-state balances
- Invariant to test: reserve-matched foreign assets must not be spendable as if they were a different local asset class
- Expected Immunefi impact: Critical - direct loss of funds or unbacked asset movement
- Fast validation: xcm-emulator test for reserve classification and settlement of the HOLLAR-like asset path
