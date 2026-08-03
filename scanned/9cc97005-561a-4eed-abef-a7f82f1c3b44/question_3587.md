# Q3587: reputation-consumption replay via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
