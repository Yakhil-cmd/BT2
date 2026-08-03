# Q3505: community-treasury drift via polkadotxcm execute send on Encointer runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `construct_runtime! / RuntimeCall::{EncointerScheduler, EncointerCeremonies, EncointerCommunities, EncointerBalances, EncointerBazaar, EncointerReputationCommitments, EncointerFaucet, EncointerTreasuries, EncointerOfflinePayment, EncointerReputationRings}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
