# Q3344: revenue-claim replay via proxy proxy multisig as on Coretime Kusama runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls on Coretime Kusama runtime and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: xcm-emulator test if the path depends on relay-side transact or burn messaging
