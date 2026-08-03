# Q3287: revenue-claim replay via utility batch all around on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple Broker effects in one block on Coretime allocator logic and control core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state so that `CoretimeAllocator::{request_core_count, request_revenue_info_at, assign_core}` turns a normal broker action into a more privileged or differently metered transition through proxy, batch, or XCM composition, breaking the invariant that coretime revenue and burn accounting must never drift from actual user-visible balances, and leading to critical - permanent freeze of user funds or purchased coretime?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `CoretimeAllocator::{request_core_count, request_revenue_info_at, assign_core}`
- Entrypoint: `Utility::batch_all` around multiple Broker effects in one block
- Attacker controls: core allocation timing, revenue claim timing, and user-controlled credit or beneficiary state
- Exploit idea: turns a normal broker action into a more privileged or differently metered transition through proxy, batch, or XCM composition
- Invariant to test: coretime revenue and burn accounting must never drift from actual user-visible balances
- Expected Immunefi impact: Critical - permanent freeze of user funds or purchased coretime
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
