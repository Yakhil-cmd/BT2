# Q2642: proxy-assisted identity escape via proxy proxy multisig as on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Polkadot runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: makes identity deposits, slashes, or refunds settle to a different account or treasury destination than intended
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
