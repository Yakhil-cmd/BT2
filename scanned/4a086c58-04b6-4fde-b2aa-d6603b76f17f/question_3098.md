# Q3098: identity refund double-count via identity set identity clear on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `impl pallet_identity::Config` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
