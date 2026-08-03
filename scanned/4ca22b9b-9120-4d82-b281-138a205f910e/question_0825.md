# Q825: crowdloan exit inconsistency via crowdloan contribute withdraw on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Crowdloan::{contribute, withdraw}` on Polkadot Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `impl pallet_rc_migrator::Config` obtains a second payout, claim, or withdrawal after a first transition partially succeeded, breaking the invariant that user-controlled batching must not bypass staking, pool, claim, or proxy restrictions, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Crowdloan::{contribute, withdraw}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: obtains a second payout, claim, or withdrawal after a first transition partially succeeded
- Invariant to test: user-controlled batching must not bypass staking, pool, claim, or proxy restrictions
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state
