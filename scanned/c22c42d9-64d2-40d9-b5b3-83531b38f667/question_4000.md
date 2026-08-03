# Q4000: reward-bound mismatch via nominationpools claim payout withdraw on Relay common payout logic

## Question
Can an unprivileged attacker enter through `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary on Relay common payout logic and control stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity so that `relay_era_payout` causes `relay_era_payout` to drift from the balances users and the treasury can actually realize, breaking the invariant that equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone, and leading to high - system-wide accounting error in staking payout?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary
- Attacker controls: stake ratios, total stakable amount, and legacy-auction proportion changes induced by realistic user staking activity
- Exploit idea: causes `relay_era_payout` to drift from the balances users and the treasury can actually realize
- Invariant to test: equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone
- Expected Immunefi impact: High - system-wide accounting error in staking payout
- Fast validation: integration test around the exact era transition and payout sequence
