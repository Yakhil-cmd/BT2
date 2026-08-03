# Q3121: coretime debit-allocation split via runtimecall broker signed user on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::Broker` signed user path on Coretime Polkadot runtime and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded, breaking the invariant that a user-triggered broker consequence must not be replayable after the underlying state changed, and leading to critical - permanent freeze of user funds or purchased coretime?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `RuntimeCall::Broker` signed user path
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded
- Invariant to test: a user-triggered broker consequence must not be replayable after the underlying state changed
- Expected Immunefi impact: Critical - permanent freeze of user funds or purchased coretime
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
