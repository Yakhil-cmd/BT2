# Q3997: era-payout saturation drift via nominationpools claim payout withdraw on Relay common payout logic

## Question
Can an unprivileged attacker enter through `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary on Relay common payout logic and control reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries so that `relay_era_payout` makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths, breaking the invariant that rounding and saturation must not create claimable value that is not backed by issuance, and leading to high - system-wide accounting error in staking payout?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary
- Attacker controls: reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries
- Exploit idea: makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths
- Invariant to test: rounding and saturation must not create claimable value that is not backed by issuance
- Expected Immunefi impact: High - system-wide accounting error in staking payout
- Fast validation: integration test around the exact era transition and payout sequence
