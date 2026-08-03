# Q3541: community-treasury drift via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
