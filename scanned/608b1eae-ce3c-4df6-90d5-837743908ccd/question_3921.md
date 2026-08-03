# Q3921: reward-bound mismatch via nominationpools claim payout withdraw on Relay common payout logic

## Question
Can an unprivileged attacker enter through `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary on Relay common payout logic and control edge-case ratios that maximize rounding, saturation, and treasury-rest interactions so that `relay_era_payout` makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths, breaking the invariant that equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary
- Attacker controls: edge-case ratios that maximize rounding, saturation, and treasury-rest interactions
- Exploit idea: makes the same economic state produce inconsistent payout outcomes when reached through different user-triggered paths
- Invariant to test: equivalent economic states must not produce materially different payout outcomes because of user-controlled ordering alone
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: property test over realistic staking-state ranges and ordering paths with payout bound assertions
