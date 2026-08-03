# Q2627: proxy-assisted identity escape via identity set identity clear on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
