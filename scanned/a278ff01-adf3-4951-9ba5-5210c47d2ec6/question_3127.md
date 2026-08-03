# Q3127: burn-accounting drift via polkadotxcm execute on Coretime Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Coretime Polkadot runtime and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to critical - permanent freeze of user funds or purchased coretime?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: Critical - permanent freeze of user funds or purchased coretime
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
