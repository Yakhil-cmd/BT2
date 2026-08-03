# Q3563: reputation-consumption replay via runtimecall encointerceremonies signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCeremonies` signed user path on Encointer runtime and control offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries so that `impl_runtime_apis! / XCM payment and dry-run APIs` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerCeremonies` signed user path
- Attacker controls: offline payment payloads, reputation commitments, and treasury beneficiaries replayed across ceremony boundaries
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: runtime integration test over the exact community, ceremony, and payout sequence with balance and reputation assertions
