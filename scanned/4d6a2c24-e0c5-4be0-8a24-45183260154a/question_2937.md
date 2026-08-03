# Q2937: refund-beneficiary mismatch via identity set identity clear on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
