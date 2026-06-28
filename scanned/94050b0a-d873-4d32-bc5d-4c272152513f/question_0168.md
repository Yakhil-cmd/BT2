# Q168: submit_with_args() version split through borsh decoding of `SubmitArgs`

## Question
Can an attacker exploit a compatibility split around borsh decoding of `SubmitArgs` so one transaction form is accepted by one parser or branch and handled differently by another branch in `submit_with_args()` on the Aurora engine contract, yielding Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `borsh decoding of `SubmitArgs``
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: abuse typed-transaction or compatibility boundaries around the subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run the same logical transaction through each reachable parsing branch and compare normalized fields, status, gas, and state changes. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
