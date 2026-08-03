# Q894: pool-versus-staking split via nominationpools join bond extra on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `NominationPools::{join, bond_extra, unbond, withdraw_unbonded, claim_payout}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: forces a state transition that should be blocked by lock, freeze, pending-unlock, or announcement rules
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
