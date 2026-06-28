# Q174: submit_with_args() delegation gap at borsh decoding of `SubmitArgs`

## Question
Can an attacker abuse delegated code or authorization semantics through `submit_with_args()` on the Aurora engine contract so that borsh decoding of `SubmitArgs` trusts the wrong code-bearing account state, enabling unauthorized value movement or Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `borsh decoding of `SubmitArgs``
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: target delegated-account behavior and any code-presence assumptions at the subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Insolvency
- Fast validation: Construct delegated and non-delegated sender states around the same logical call and assert auth, fee, and execution behavior stay consistent. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
