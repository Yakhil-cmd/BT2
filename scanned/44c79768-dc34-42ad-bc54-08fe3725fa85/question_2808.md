# Q2808: sub-account deposit leak via identity set identity clear on People Polkadot identity config

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot identity config and control locations or treasury-routing state that receive slashed identity deposits so that `IdentityAdminOrigin` lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed, breaking the invariant that encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly, and leading to critical - permanent freeze of deposits or balances tied to identity lifecycle?

## Target
- File/function: `system-parachains/people/people-polkadot/src/people.rs` :: `IdentityAdminOrigin`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: locations or treasury-routing state that receive slashed identity deposits
- Exploit idea: lets a user reclaim or avoid an identity-related deposit after the chain has already treated it as consumed
- Invariant to test: encoded identity fields must not let a signed user reach unauthorized privileged outcomes indirectly
- Expected Immunefi impact: Critical - permanent freeze of deposits or balances tied to identity lifecycle
- Fast validation: runtime integration test over set_identity, set_subs, clear_identity, and username lifecycle boundaries
