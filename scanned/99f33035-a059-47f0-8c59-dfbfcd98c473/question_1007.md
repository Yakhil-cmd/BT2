# Q1007: cross-pallet hold mismatch via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping so that `impl pallet_rc_migrator::Config` creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping
- Exploit idea: creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
