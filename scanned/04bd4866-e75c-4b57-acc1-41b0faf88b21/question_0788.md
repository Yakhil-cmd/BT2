# Q788: claim-path state divergence via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_nomination_pools::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that user-controlled batching must not bypass staking, pool, claim, or proxy restrictions, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: user-controlled batching must not bypass staking, pool, claim, or proxy restrictions
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
