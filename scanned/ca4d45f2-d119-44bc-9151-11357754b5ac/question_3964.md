# Q3964: reward-bound mismatch via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity so that `relay_era_payout` makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths, breaking the invariant that rounding and saturation must not create claimable value that is not backed by issuance, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity
- Exploit idea: makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths
- Invariant to test: rounding and saturation must not create claimable value that is not backed by issuance
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: integration test around the exact era transition and payout sequence
