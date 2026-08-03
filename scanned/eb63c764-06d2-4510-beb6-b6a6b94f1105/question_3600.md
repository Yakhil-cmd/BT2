# Q3600: offline-payment double-spend via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
