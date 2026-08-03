# Q3579: reputation-consumption replay via runtimecall encointerceremonies signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCeremonies` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerCeremonies` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
