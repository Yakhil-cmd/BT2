# Q3267: revenue-claim replay via runtimecall broker signed user on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `RuntimeCall::Broker` signed user path that triggers allocator, burn, or revenue logic on Coretime allocator logic and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `burn_at_relay` lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded, breaking the invariant that a user-triggered broker consequence must not be replayable after the underlying state changed, and leading to critical - direct loss of funds or unbacked coretime credit?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `RuntimeCall::Broker` signed user path that triggers allocator, burn, or revenue logic
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: lets a user replay or reorder a purchase, revenue, or assignment consequence after the first transition partially succeeded
- Invariant to test: a user-triggered broker consequence must not be replayable after the underlying state changed
- Expected Immunefi impact: Critical - direct loss of funds or unbacked coretime credit
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
