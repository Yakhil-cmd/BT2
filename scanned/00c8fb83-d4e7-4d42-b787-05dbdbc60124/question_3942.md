# Q3942: stake-ratio ordering edge via nominationpools claim payout withdraw on Relay common payout logic

## Question
Can an unprivileged attacker enter through `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary on Relay common payout logic and control reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries so that `relay_era_payout` causes `relay_era_payout` to drift from the balances users and the treasury can actually realize, breaking the invariant that rounding and saturation must not create claimable value that is not backed by issuance, and leading to critical - unbacked reward payout or treasury drift with user-withdrawable value?

## Target
- File/function: `relay/common/src/lib.rs` :: `relay_era_payout`
- Entrypoint: `NominationPools::{claim_payout, withdraw_unbonded}` around an era boundary
- Attacker controls: reward-payout timing around large stake movement, nomination-pool movement, or unlock boundaries
- Exploit idea: causes `relay_era_payout` to drift from the balances users and the treasury can actually realize
- Invariant to test: rounding and saturation must not create claimable value that is not backed by issuance
- Expected Immunefi impact: Critical - unbacked reward payout or treasury drift with user-withdrawable value
- Fast validation: property test over realistic staking-state ranges and ordering paths with payout bound assertions
