# Q845: reward-accounting drift via claims claim claim attest on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Claims::{claim, claim_attest, move_claim}` on Polkadot Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant, breaking the invariant that claimable value must never exceed backing funds or issuance, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Claims::{claim, claim_attest, move_claim}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant
- Invariant to test: claimable value must never exceed backing funds or issuance
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
