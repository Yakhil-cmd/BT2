# Q3630: cross-ceremony state bleed via runtimecall encointerbalances or encointerofflinepayment on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
