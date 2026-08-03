# Q3580: offline-payment double-spend via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control XCM or proxy execution layered around community payout or reputation-consuming flows so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to high - severe degradation or halt of a critical community-payment path?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: XCM or proxy execution layered around community payout or reputation-consuming flows
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: High - severe degradation or halt of a critical community-payment path
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
