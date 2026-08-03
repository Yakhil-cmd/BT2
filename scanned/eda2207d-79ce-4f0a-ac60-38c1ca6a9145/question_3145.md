# Q3145: coretime debit-allocation split via proxy proxy multisig as on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls on Coretime Polkadot runtime and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` creates a path where burn, revenue, or allocation bookkeeping is finalized in one subsystem but not the other, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: creates a path where burn, revenue, or allocation bookkeeping is finalized in one subsystem but not the other
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
