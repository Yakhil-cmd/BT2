# Q3612: offline-payment double-spend via polkadotxcm execute send on Encointer runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
