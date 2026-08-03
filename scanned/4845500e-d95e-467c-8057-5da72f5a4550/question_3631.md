# Q3631: reputation-consumption replay via runtimecall encointerceremonies signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCeremonies` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerCeremonies` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution
