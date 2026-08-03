# Q3162: proxy-batched broker escape via polkadotxcm execute on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Coretime Polkadot runtime and control signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: xcm-emulator test if the path depends on relay-side transact or burn messaging
