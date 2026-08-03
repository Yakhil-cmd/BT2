# Q3639: reputation-consumption replay via proxy proxy utility batch on Encointer runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Utility::batch_all` around Encointer calls on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Utility::batch_all` around Encointer calls
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
