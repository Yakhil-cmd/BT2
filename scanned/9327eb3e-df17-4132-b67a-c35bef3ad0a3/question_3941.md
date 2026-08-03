# Q3941: era-payout saturation drift via nominationpools claim payout withdraw on Relay common payout logic

## Question
Can an unprivileged attacker enter through `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary on Relay common payout logic and control edge-case ratios that maximize rounding, saturation, and treasury-rest interactions so that `relay_era_payout` lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition, breaking the invariant that equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone, and leading to high - system-wide accounting error in staking payout?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary
- Attacker controls: edge-case ratios that maximize rounding, saturation, and treasury-rest interactions
- Exploit idea: lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition
- Invariant to test: equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone
- Expected Immunefi impact: High - system-wide accounting error in staking payout
- Fast validation: integration test around the exact era transition and payout sequence
