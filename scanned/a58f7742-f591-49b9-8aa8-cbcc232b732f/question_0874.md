# Q874: unlock-ordering mismatch via claims claim claim attest on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Claims::{claim, claim_attest, move_claim}` on Polkadot Relay runtime and control crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries so that `impl pallet_rc_migrator::Config` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to critical - direct loss of funds or unbacked withdrawal?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Claims::{claim, claim_attest, move_claim}`
- Attacker controls: crowdloan contribution and withdrawal timing around lease expiry and unlock boundaries
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: Critical - direct loss of funds or unbacked withdrawal
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
