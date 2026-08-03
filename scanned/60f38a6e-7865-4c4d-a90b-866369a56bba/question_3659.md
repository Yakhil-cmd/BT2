# Q3659: reputation-consumption replay via runtimecall encointertreasuries signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerTreasuries` signed user path on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes community balances, treasuries, and reputation state disagree about which value was already spent or earned, breaking the invariant that community treasury and issued balances must always reconcile after user-triggered flows, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerTreasuries` signed user path
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: makes community balances, treasuries, and reputation state disagree about which value was already spent or earned
- Invariant to test: community treasury and issued balances must always reconcile after user-triggered flows
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
