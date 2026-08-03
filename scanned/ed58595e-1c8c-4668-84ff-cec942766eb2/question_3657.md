# Q3657: community-treasury drift via runtimecall encointercommunities signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCommunities` signed user path on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerCommunities` signed user path
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution
