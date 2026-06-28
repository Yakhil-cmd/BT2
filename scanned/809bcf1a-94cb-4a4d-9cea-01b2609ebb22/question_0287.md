# Q287: submit_with_args() reorder race at code-bearing sender rejection in `RejectCallerWithCode` / EIP-3607 logic

## Question
Can an attacker reorder two user-controlled submissions through `submit_with_args()` on the Aurora engine contract so that code-bearing sender rejection in `RejectCallerWithCode` / EIP-3607 logic observes stale state for one call and fresh state for the other, creating a double-spend, stale-refund, or stale-auth condition that leads to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `code-bearing sender rejection in `RejectCallerWithCode` / EIP-3607 logic`
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: use back-to-back submissions to hit stale-state assumptions at the named subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run paired transactions in both orders and assert nonce, sender balance, and any derived reward or auth state stay serializable. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
