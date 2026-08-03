# Q3529: community-treasury drift via runtimecall encointerbalances or encointerofflinepayment on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
