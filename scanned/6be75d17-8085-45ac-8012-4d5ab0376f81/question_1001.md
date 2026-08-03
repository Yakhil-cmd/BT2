# Q1001: crowdloan exit inconsistency via staking bond unbond rebond on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Staking::{bond, unbond, rebond, nominate, payout_stakers}` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_nomination_pools::Config` converts a user-controlled call into a more privileged or differently metered runtime path, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Staking::{bond, unbond, rebond, nominate, payout_stakers}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: converts a user-controlled call into a more privileged or differently metered runtime path
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
