# Q832: double-withdraw edge via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_staking::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
