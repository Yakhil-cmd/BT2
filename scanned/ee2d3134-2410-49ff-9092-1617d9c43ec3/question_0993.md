# Q993: crowdloan exit inconsistency via nominationpools join bond extra on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Kusama Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - network-wide halt or stuck critical queue?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - network-wide halt or stuck critical queue
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
