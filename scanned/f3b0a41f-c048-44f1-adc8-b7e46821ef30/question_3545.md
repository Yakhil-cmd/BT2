# Q3545: community-treasury drift via runtimecall encointertreasuries signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerTreasuries` signed user path on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `RuntimeCall::EncointerTreasuries` signed user path
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
