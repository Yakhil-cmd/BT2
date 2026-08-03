# Q865: crowdloan exit inconsistency via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_staking::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
