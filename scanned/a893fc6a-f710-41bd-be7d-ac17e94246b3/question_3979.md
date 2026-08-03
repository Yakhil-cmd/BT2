# Q3979: stake-ratio ordering edge via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control edge-case ratios that maximize rounding, saturation, and treasury-rest interactions so that `relay_era_payout` causes `relay_era_payout` to drift from the balances users and the treasury can actually realize, breaking the invariant that staking payout plus treasury rest must remain bounded by the intended issuance schedule, and leading to high - system-wide accounting error in staking payout?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: edge-case ratios that maximize rounding, saturation, and treasury-rest interactions
- Exploit idea: causes `relay_era_payout` to drift from the balances users and the treasury can actually realize
- Invariant to test: staking payout plus treasury rest must remain bounded by the intended issuance schedule
- Expected Immunefi impact: High - system-wide accounting error in staking payout
- Fast validation: integration test around the exact era transition and payout sequence
