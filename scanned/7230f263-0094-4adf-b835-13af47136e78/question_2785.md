# Q2785: treasury-routing mismatch via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `impl pallet_identity::Config` causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `impl pallet_identity::Config`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: causes `IdentityInfo`, deposit accounting, and treasury-routing logic to disagree about how much value remains claimable
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: stateful fuzz test for repeated identity mutation with balance assertions before and after refund/slash
