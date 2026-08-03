# Q3629: community-treasury drift via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption, breaking the invariant that each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: batched calls spanning balances, ceremonies, treasuries, bazaar, and democracy modules
- Exploit idea: causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption
- Invariant to test: each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
