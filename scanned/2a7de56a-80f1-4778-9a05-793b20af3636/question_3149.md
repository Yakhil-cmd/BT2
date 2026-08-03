# Q3149: coretime debit-allocation split via polkadotxcm execute on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Coretime Polkadot runtime and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to high - severe availability loss on the coretime purchase or assignment path?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: High - severe availability loss on the coretime purchase or assignment path
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
