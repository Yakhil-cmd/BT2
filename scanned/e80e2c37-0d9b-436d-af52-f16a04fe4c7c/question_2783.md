# Q2783: username-expiry accounting drift via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control username expiration and grace-period boundaries combined with balance-moving calls so that `IdentityAdminOrigin` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that username and sub-account lifecycle state must not strand or duplicate user funds, and leading to critical - direct loss of user funds through bad refund or slash accounting?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: username expiration and grace-period boundaries combined with balance-moving calls
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: username and sub-account lifecycle state must not strand or duplicate user funds
- Expected Immunefi impact: Critical - direct loss of user funds through bad refund or slash accounting
- Fast validation: targeted test proving whether treasury routing resolves to the expected account after adversarial input
