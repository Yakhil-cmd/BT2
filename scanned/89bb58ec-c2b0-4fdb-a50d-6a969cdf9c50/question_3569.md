# Q3569: community-treasury drift via runtimecall encointercommunities signed user on Encointer runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::EncointerCommunities` signed user path on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated, breaking the invariant that XCM-assisted flows must not mint, unlock, or strand more value than they debit locally, and leading to critical - permanent freeze of community funds?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `RuntimeCall::EncointerCommunities` signed user path
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: lets a signed user cross community or ceremony boundaries that the runtime expected to remain isolated
- Invariant to test: XCM-assisted flows must not mint, unlock, or strand more value than they debit locally
- Expected Immunefi impact: Critical - permanent freeze of community funds
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
