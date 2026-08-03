# Q2909: identity-deposit drift via identity set identity clear on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
