# Q3325: proxy-batched broker escape via runtimecall broker signed user on Coretime allocator logic

## Question
Can an unprivileged attacker enter through `RuntimeCall::Broker` signed user path that triggers allocator, burn, or revenue logic on Coretime allocator logic and control XCM execution that lands in the same block as coretime purchase, burn, or assignment logic so that `burn_at_relay` makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased, breaking the invariant that every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path, and leading to critical - permanent freeze of user funds or purchased coretime?

## Target
- File/function: `system-parachains/coretime/coretime-polkadot/src/coretime.rs` :: `burn_at_relay`
- Entrypoint: `RuntimeCall::Broker` signed user path that triggers allocator, burn, or revenue logic
- Attacker controls: XCM execution that lands in the same block as coretime purchase, burn, or assignment logic
- Exploit idea: makes user debits, relay-side crediting, and local core allocation disagree about how much paid coretime was actually purchased
- Invariant to test: every unit of purchased or transferred coretime must be backed by exactly one debit and one allocation path
- Expected Immunefi impact: Critical - permanent freeze of user funds or purchased coretime
- Fast validation: runtime integration test that executes the signed broker path and compares local debit, relay-bound message, and final allocation state
