# Q212: submit_with_args() pause or silo bypass through relayer address derivation from `predecessor_address`

## Question
Can an attacker choose transaction shape or sender identity through `submit_with_args()` on the Aurora engine contract so that relayer address derivation from `predecessor_address` bypasses a pause, whitelist, or silo expectation that later execution assumes is enforced, producing Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `relayer address derivation from `predecessor_address``
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: use alternative sender, access-list, or typed-transaction paths to slip past the intended gate near the subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Insolvency
- Fast validation: Enable the relevant restriction in test state, then exercise alternate transaction forms and assert they are all rejected consistently. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
