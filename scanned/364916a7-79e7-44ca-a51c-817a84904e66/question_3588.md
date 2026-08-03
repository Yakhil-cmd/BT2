# Q3588: offline-payment double-spend via runtimecall encointerbalances or encointerofflinepayment on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
