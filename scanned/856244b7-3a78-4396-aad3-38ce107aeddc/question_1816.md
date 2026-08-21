# Q1816: delete-account fund escape in transactions::decode_signed_transaction

## Question
Can an unprivileged attacker who submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account, controlling beneficiary id, remaining locked balance, and pending incoming receipts, drive `chain/jsonrpc/src/api/transactions.rs::decode_signed_transaction` to delete an account while receipts are still in flight so the transferred value is credited twice or lost, breaking the invariant that deleting an account moves its entire balance to the beneficiary exactly once, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `chain/jsonrpc/src/api/transactions.rs` -> `decode_signed_transaction`
- Entrypoint: unprivileged attacker submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account
- Attacker controls: beneficiary id, remaining locked balance, and pending incoming receipts
- Exploit idea: delete an account while receipts are still in flight so the transferred value is credited twice or lost
- Invariant to test: deleting an account moves its entire balance to the beneficiary exactly once
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
