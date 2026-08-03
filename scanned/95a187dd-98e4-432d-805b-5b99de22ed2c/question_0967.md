# Q967: cross-pallet hold mismatch via crowdloan contribute withdraw on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Kusama Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `impl pallet_nomination_pools::Config` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `impl pallet_nomination_pools::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
