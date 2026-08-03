# Q3577: community-treasury drift via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
