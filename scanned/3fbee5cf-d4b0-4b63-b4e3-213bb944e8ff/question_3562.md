# Q3562: cross-ceremony state bleed via runtimecall encointerbalances or encointerofflinepayment on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerBalances` or `EncointerOfflinePayment` signed user path
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: causes a payout, faucet action, or bazaar settlement to finalize locally without the matching burn, hold, or reputation consumption
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: xcm or proxy integration test if the path depends on aliased or remote execution
