# Q781: reward-accounting drift via proxy proxy multisig as on Polkadot Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Polkadot Relay runtime and control a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state, breaking the invariant that XCM-triggered and local transitions must preserve the same accounting rules, and leading to critical - permanent freeze of user funds?

## Target
- File/function: `relay/polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: a batched combination of proxy, multisig, XCM, and staking-related calls in one transaction
- Exploit idea: makes two runtime subsystems disagree about the same user's balance, points, claimability, or unlocking state
- Invariant to test: XCM-triggered and local transitions must preserve the same accounting rules
- Expected Immunefi impact: Critical - permanent freeze of user funds
- Fast validation: runtime integration test around the exact batch, unlock, or claim boundary
