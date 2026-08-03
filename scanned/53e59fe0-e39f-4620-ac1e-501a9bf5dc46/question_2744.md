# Q2744: sub-account deposit leak via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityInfo / fields()` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityInfo / fields()`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
