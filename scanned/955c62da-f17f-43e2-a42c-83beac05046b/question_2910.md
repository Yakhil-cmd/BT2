# Q2910: sub-account lock reuse via polkadotxcm execute send on People Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Kusama runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
