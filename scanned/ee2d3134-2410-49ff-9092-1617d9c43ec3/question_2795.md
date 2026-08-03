# Q2795: username-expiry accounting drift via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations so that `IdentityAdminOrigin` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that treasury routing for slashed deposits must never be attacker-controlled from a signed path, and leading to high - unauthorized state transition affecting another account or treasury routing?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity metadata, username state, and sub-account deposit sizing around repeated set and clear operations
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: treasury routing for slashed deposits must never be attacker-controlled from a signed path
- Expected Immunefi impact: High - unauthorized state transition affecting another account or treasury routing
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
