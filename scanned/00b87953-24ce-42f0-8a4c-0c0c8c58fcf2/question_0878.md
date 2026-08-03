# Q878: pool-versus-staking split via claims claim claim attest on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Claims::{claim, claim_attest, move_claim}` on Polkadot Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Claims::{claim, claim_attest, move_claim}`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: creates a cross-pallet ordering edge where the final state violates the intended staking, claims, or crowdloan invariant
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
