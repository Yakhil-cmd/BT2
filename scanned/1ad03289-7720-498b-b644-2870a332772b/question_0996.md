# Q996: pool-versus-staking split via proxy proxy multisig as on Kusama Relay runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Kusama Relay runtime and control attacker-chosen claim parameters, destination accounts, or attestation ordering so that `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}` makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw, breaking the invariant that unlocking state, holds, and reserves must stay consistent across all touched pallets, and leading to high - unintended runtime behaviour with concrete user loss?

## Target
- File/function: `relay/kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Staking, NominationPools, Claims, Crowdloan, XcmPallet, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: attacker-chosen claim parameters, destination accounts, or attestation ordering
- Exploit idea: makes issuance, rewards, or held and reserved balances drift from what users can actually withdraw
- Invariant to test: unlocking state, holds, and reserves must stay consistent across all touched pallets
- Expected Immunefi impact: High - unintended runtime behaviour with concrete user loss
- Fast validation: invariant test that repeats the sequence until a double-claim or accounting drift appears
