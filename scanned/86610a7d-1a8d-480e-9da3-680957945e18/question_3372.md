# Q3372: revenue-claim replay via runtimecall broker signed user on Coretime Kusama runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::Broker` signed user path on Coretime Kusama runtime and control signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to high - severe availability loss on the coretime purchase or assignment path?

## Target
- File/function: `system-parachains/coretime/coretime-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `RuntimeCall::Broker` signed user path
- Attacker controls: signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: High - severe availability loss on the coretime purchase or assignment path
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
