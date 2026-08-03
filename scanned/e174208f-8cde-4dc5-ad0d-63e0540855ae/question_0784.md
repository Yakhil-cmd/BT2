# Q784: double-withdraw edge via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_staking::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that no signed user can turn a normal call into a privileged or underpriced state change, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_staking::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: no signed user can turn a normal call into a privileged or underpriced state change
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
