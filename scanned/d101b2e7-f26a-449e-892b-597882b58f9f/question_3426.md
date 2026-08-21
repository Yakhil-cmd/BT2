# Q3426: outcome id collision in lib::merge

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling receipt and transaction hashes feeding execution outcome ids, drive `runtime/runtime/src/lib.rs::merge` to overwrite one execution outcome with another, breaking the invariant that execution outcome ids uniquely identify one receipt or transaction, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/lib.rs` -> `merge`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: receipt and transaction hashes feeding execution outcome ids
- Exploit idea: overwrite one execution outcome with another
- Invariant to test: execution outcome ids uniquely identify one receipt or transaction
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
