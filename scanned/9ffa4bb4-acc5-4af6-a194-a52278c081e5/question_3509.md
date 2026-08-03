# Q3509: community-treasury drift via runtimecall encointertreasuries signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerTreasuries` signed user path on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerTreasuries` signed user path
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
