# Q2656: slash-routing confusion via proxy proxy multisig as on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on People Polkadot runtime and control batched updates that mutate both identity deposits and transferable balances before finalization so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched updates that mutate both identity deposits and transferable balances before finalization
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
