# Q2651: slash-routing confusion via proxy proxy multisig as on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Polkadot runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
