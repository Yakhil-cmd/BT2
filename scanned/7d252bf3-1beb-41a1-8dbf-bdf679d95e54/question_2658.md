# Q2658: sub-account lock reuse via identity set identity clear on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
