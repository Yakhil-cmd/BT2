# Q2763: username-expiry accounting drift via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `IdentityInfo / fields()` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
