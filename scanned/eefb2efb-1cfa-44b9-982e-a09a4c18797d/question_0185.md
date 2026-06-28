# Q185: submit_with_args() sender identity confusion in the optional `max_gas_price` cap applied during `charge_gas`

## Question
Can an attacker use `submit_with_args()` on the Aurora engine contract with borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing to make the optional `max_gas_price` cap applied during `charge_gas` derive or trust the wrong sender, relayer, or delegated identity, so value or rewards move under the wrong account and cause Insolvency?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit_with_args -> engine/src/engine.rs::submit_with_alt_modexp` -> `the optional `max_gas_price` cap applied during `charge_gas``
- Entrypoint: `submit_with_args()` on the Aurora engine contract
- Attacker controls: borsh-encoded `SubmitArgs`, raw transaction bytes inside `SubmitArgs`, optional max gas price overrides, relayer account choice, and replay timing
- Exploit idea: target sender, relayer, or delegated-account interpretation around the named subtarget.
- Invariant to test: the structured submit path must preserve the same signer, fee, authorization, and refund semantics as the raw submit path
- Expected Immunefi impact: Insolvency
- Fast validation: Construct transactions where signer, predecessor, and relayer identities vary, then assert all value movement and rewards follow the intended identity only. write a Rust integration test that sends equivalent transactions through `submit()` and `submit_with_args()`, mutates the targeted field, and checks balances, nonce, logs, and status parity
