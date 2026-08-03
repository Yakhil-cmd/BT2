# Q3412: revenue-claim replay via runtimecall broker signed user on Coretime Kusama runtime

## Question
Can an unprivileged attacker enter through `RuntimeCall::Broker` signed user path on Coretime Kusama runtime and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Broker, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `RuntimeCall::Broker` signed user path
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
