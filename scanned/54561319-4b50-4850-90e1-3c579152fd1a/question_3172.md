# Q3172: revenue-claim replay via proxy proxy multisig as on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls on Coretime Polkadot runtime and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded, breaking the invariant that a user-triggered broker consequence must not be replayable after the underlying state changed, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` around Broker calls
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded
- Invariant to test: a user-triggered broker consequence must not be replayable after the underlying state changed
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: xcm-emulator test if the path depends on relay-side transact or burn messaging
