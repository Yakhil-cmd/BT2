# Q990: claim-path state divergence via crowdloan contribute withdraw on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Kusama Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_rc_migrator::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
