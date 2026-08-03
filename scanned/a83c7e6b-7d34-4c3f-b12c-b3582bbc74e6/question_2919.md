# Q2919: identity-deposit drift via proxy proxy multisig as on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Kusama runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
