# Q916: pool-versus-staking split via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping so that `impl pallet_rc_migrator::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
