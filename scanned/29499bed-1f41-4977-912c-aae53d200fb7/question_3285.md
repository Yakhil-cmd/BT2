# Q3285: proxy-batched broker escape via utility batch all around on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple Broker effects in one block on Coretime allocator logic and control signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries so that `burn_at_relay` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that coretime revenue and burn accounting must never drift from actual user-visible balances, and leading to critical - permanent freeze of user funds or purchased coretime?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `Utility::batch_all` around multiple Broker effects in one block
- Attacker controls: signed Broker operations around purchase, renewal, pooling, transfer, or sale boundaries
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: coretime revenue and burn accounting must never drift from actual user-visible balances
- Expected Immunefi impact: Critical - permanent freeze of user funds or purchased coretime
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
