# Q856: double-withdraw edge via staking bond unbond rebond on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Staking::{bond, unbond, rebond, nominate, payout_stakers}` on Polkadot Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `impl pallet_rc_migrator::Config` creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant, breaking the invariant that one pool share, claim, contribution, or unlock chunk may only be exited or consumed once, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `impl pallet_rc_migrator::Config`
- Entrypoint: `Staking::{bond, unbond, rebond, nominate, payout_stakers}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant
- Invariant to test: one pool share, claim, contribution, or unlock chunk may only be exited or consumed once
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: xcm-emulator test if the path crosses the XCM pallet before returning to local state
