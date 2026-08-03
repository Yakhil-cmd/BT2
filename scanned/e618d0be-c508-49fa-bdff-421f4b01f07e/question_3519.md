# Q3519: reputation-consumption replay via runtimecall encointertreasuries signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerTreasuries` signed user path on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerTreasuries` signed user path
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
