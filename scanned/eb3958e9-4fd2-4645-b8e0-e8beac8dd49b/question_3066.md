# Q3066: identity refund double-count via identity set identity clear on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityInfo / fields()` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
