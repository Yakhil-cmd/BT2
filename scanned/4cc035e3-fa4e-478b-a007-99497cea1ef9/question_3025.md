# Q3025: treasury-routing mismatch via identity set identity clear on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `IdentityInfo / fields()` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that identity-related deposits must be debited, refunded, or slashed exactly once, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: identity-related deposits must be debited, refunded, or slashed exactly once
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
