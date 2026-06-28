# Q16: submit() zero-address edge in typed-transaction dispatch in `EthTransactionKind::try_from`

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` on the Aurora engine contract so that typed-transaction dispatch in `EthTransactionKind::try_from` routes the transaction differently from the rest of the engine and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit -> engine/src/engine.rs::submit_with_alt_modexp` -> `typed-transaction dispatch in `EthTransactionKind::try_from``
- Entrypoint: `submit()` on the Aurora engine contract
- Attacker controls: raw signed transaction bytes, calldata, `to`/create selection, gas limits, fee caps, access lists, authorization lists, relayer account choice, and transaction replay timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: every submitted transaction must be parsed once, attributed to one signer on one chain, charged once, and either commit or refund consistently
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. write a Rust integration test that submits crafted raw transaction bytes through `submit()` and asserts sender balance, relayer reward, nonce, logs, and post-state remain consistent
