# Q309: submit_with_args() call-create ambiguity near promise-log filtering in `filter_promises_from_logs`

## Question
Can an attacker make promise-log filtering in `filter_promises_from_logs` misclassify a transaction as a call when it should be a create, or vice versa, through `submit_with_args()` on the Aurora engine contract, so the wrong path consumes value or updates state and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `promise-log filtering in `filter_promises_from_logs``
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: target transaction fields that decide create-versus-call routing around the named subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Exercise both empty-recipient and non-empty-recipient variants with identical payloads and assert only the intended route mutates code and balances. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
