# Q3389: coretime debit-allocation split via polkadotxcm execute on Coretime Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Coretime Kusama runtime and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
