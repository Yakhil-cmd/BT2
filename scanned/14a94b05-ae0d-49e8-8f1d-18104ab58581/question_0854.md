# Q854: pool-versus-staking split via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_nomination_pools::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
