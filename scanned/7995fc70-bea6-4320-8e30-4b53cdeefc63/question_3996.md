# Q3996: reward-bound mismatch via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity so that `relay_era_payout` lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition, breaking the invariant that staking payout plus treasury rest must remain bounded by the intended issuance schedule, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity
- Exploit idea: lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition
- Invariant to test: staking payout plus treasury rest must remain bounded by the intended issuance schedule
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: integration test around the exact era transition and payout sequence
