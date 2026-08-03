# Q811: cross-pallet hold mismatch via staking bond unbond rebond on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Staking::{bond, unbond, rebond, nominate, payout_stakers}` on Polkadot Relay runtime and control fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Staking::{bond, unbond, rebond, nominate, payout_stakers}`
- Attacker controls: fee-paying and fee-waived paths that touch the same balance, hold, reserve, or unlock bookkeeping
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
