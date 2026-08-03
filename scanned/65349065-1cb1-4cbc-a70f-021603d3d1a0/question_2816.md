# Q2816: sub-account deposit leak via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control inputs that maximize encoded field usage while the same account is proxied or batched so that `impl pallet_identity::Config` creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: inputs that maximize encoded field usage while the same account is proxied or batched
- Exploit idea: creates a sequencing edge where identity cleanup and concurrent value transfer leave funds permanently stranded or duplicated
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
