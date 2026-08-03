# Q3940: reward-bound mismatch via staking payout stakers and on Relay common payout logic

## Question
Can an unprivileged attacker enter through `Staking::payout_stakers` and era transition user paths on Relay common payout logic and control reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries so that `relay_era_payout` causes `relay_era_payout` to drift from the balances users and the treasury can actually realize, breaking the invariant that rounding and saturation must not create claimable value that is not backed by issuance, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `Staking::payout_stakers` and era transition user paths
- Attacker controls: reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries
- Exploit idea: causes `relay_era_payout` to drift from the balances users and the treasury can actually realize
- Invariant to test: rounding and saturation must not create claimable value that is not backed by issuance
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: integration test around the exact era transition and payout sequence
