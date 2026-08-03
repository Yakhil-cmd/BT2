# Q3549: community-treasury drift via runtimecall encointerbalances or encointerofflinepayment on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution
