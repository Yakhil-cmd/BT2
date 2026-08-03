# Q873: crowdloan exit inconsistency via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `impl pallet_rc_migrator::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: stateful fuzz test comparing pre and post balances, holds, reserves, and points
