# Q3566: cross-ceremony state bleed via runtimecall encointerceremonies signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCeremonies` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerCeremonies` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
