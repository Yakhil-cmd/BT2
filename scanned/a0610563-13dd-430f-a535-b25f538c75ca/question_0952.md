# Q952: unlock-ordering mismatch via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `impl pallet_rc_migrator::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
