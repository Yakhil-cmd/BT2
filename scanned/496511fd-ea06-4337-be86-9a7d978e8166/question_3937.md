# Q3937: era-payout saturation drift via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control edge-case ratios that maximize rounding, saturation, and treasury-rest interactions so that `relay_era_payout` makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths, breaking the invariant that staking payout plus treasury rest must remain bounded by the intended issuance schedule, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: edge-case ratios that maximize rounding, saturation, and treasury-rest interactions
- Exploit idea: makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths
- Invariant to test: staking payout plus treasury rest must remain bounded by the intended issuance schedule
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: integration test around the exact era transition and payout sequence
