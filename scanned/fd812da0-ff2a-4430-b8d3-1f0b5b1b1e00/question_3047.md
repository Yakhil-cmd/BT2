# Q3047: username-expiry accounting drift via identity set identity clear on People Kusama identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `impl pallet_identity::Config` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-kusama/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
