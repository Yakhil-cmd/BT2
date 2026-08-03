# Q3272: coretime debit-allocation split via utility batch all around on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple Broker effects in one block on Coretime allocator logic and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `burn_at_relay` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that signed users must not gain extra relay-side effects through batching or aliasing local execution, and leading to high - severe availability loss on the coretime purchase or assignment path?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `Utility::batch_all` around multiple Broker effects in one block
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: signed users must not gain extra relay-side effects through batching or aliasing local execution
- Expected Immunefi impact: High - severe availability loss on the coretime purchase or assignment path
- Fast validation: xcm-emulator test if the path depends on relay-side transact or burn messaging
