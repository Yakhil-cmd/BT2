# Q3986: stake-ratio ordering edge via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity so that `relay_era_payout` lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition, breaking the invariant that rounding and saturation must not create claimable value that is not backed by issuance, and leading to high - system-wide accounting error in staking payout?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity
- Exploit idea: lets a sequence of realistic stake changes turn one era's payout into an over-credit or under-burn condition
- Invariant to test: rounding and saturation must not create claimable value that is not backed by issuance
- Expected Immunefi impact: High - system-wide accounting error in staking payout
- Fast validation: property test over realistic staking-state ranges and ordering paths with payout bound assertions
