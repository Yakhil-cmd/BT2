# Q1022: claim-path state divergence via crowdloan contribute withdraw on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Kusama Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_nomination_pools::Config` makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
