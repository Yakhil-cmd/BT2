# Q966: claim-path state divergence via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping so that `impl pallet_nomination_pools::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
