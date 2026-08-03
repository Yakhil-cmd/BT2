# Q920: unlock-ordering mismatch via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: repeated user-triggered pool joins, exits, or payouts around reward and slash boundaries
- Exploit idea: creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
