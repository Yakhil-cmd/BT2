# Q2904: identity-deposit drift via identity set identity clear on People Kusama runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Kusama runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
