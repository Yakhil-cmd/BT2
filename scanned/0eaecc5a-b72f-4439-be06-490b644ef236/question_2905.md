# Q2905: sub-account lock reuse via proxy proxy multisig as on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Kusama runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
