# Q3299: revenue-claim replay via utility batch all around on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple Broker effects in one block on Coretime allocator logic and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `burn_at_relay` lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded, breaking the invariant that coretime revenue and burn accounting must never drift from actual user-visible balances, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `Utility::batch_all` around multiple Broker effects in one block
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded
- Invariant to test: coretime revenue and burn accounting must never drift from actual user-visible balances
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
