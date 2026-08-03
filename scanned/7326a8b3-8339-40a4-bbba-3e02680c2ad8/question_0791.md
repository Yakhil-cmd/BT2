# Q791: proxy-batch privilege widening via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions so that `impl pallet_rc_migrator::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: nested XCM execution with attacker-chosen asset, beneficiary, and origin-shaping instructions
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
