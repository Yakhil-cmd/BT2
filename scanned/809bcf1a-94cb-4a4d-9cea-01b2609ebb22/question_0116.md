# Q116: submit() zero-address edge in intrinsic gas enforcement in `NormalizedEthTransaction::intrinsic_gas`

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` on the Aurora engine contract so that intrinsic gas enforcement in `NormalizedEthTransaction::intrinsic_gas` routes the transaction differently from the rest of the engine and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit -> engine/src/engine.rs::submit_with_alt_modexp` -> `intrinsic gas enforcement in `NormalizedEthTransaction::intrinsic_gas``
- Entrypoint: `submit()` on the Aurora engine contract
- Attacker controls: raw signed transaction bytes, calldata, `to`/create selection, gas limits, fee caps, access lists, authorization lists, relayer account choice, and transaction replay timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: every submitted transaction must be parsed once, attributed to one signer on one chain, charged once, and either commit or refund consistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that submits crafted raw transaction bytes through `submit()` and asserts sender balance, relayer reward, nonce, logs, and post-state remain consistent
