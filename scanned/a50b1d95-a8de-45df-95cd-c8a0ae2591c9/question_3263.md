# Q3263: revenue-claim replay via utility batch all around on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `Utility::batch_all` around multiple Broker effects in one block on Coretime allocator logic and control batched proxy and multisig execution that changes broker state and then consumes the result immediately so that `burn_at_relay` turns a normal broker action into a more privileged or differently metered transition through proxy, batch, or XCM composition, breaking the invariant that a user-triggered broker consequence must not be replayable after the underlying state changed, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `Utility::batch_all` around multiple Broker effects in one block
- Attacker controls: batched proxy and multisig execution that changes broker state and then consumes the result immediately
- Exploit idea: turns a normal broker action into a more privileged or differently metered transition through proxy, batch, or XCM composition
- Invariant to test: a user-triggered broker consequence must not be replayable after the underlying state changed
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: stateful fuzz test around purchase, renewal, burn, and revenue-claim ordering
