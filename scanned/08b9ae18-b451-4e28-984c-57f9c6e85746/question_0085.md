# Q85: submit() sender identity confusion in sender freshness checks in `check_nonce`

## Question
Can an attacker use `submit()` on the Aurora engine contract with raw signed transaction bytes, calldata, `to`/create selection, gas limits, fee caps, access lists, authorization lists, relayer account choice, and transaction replay timing to make sender freshness checks in `check_nonce` derive or trust the wrong sender, relayer, or delegated identity, so value or rewards move under the wrong account and cause Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/evm_transactions.rs::submit -> engine/src/engine.rs::submit_with_alt_modexp` -> `sender freshness checks in `check_nonce``
- Entrypoint: `submit()` on the Aurora engine contract
- Attacker controls: raw signed transaction bytes, calldata, `to`/create selection, gas limits, fee caps, access lists, authorization lists, relayer account choice, and transaction replay timing
- Exploit idea: target sender, relayer, or delegated-account interpretation around the named subtarget.
- Invariant to test: every submitted transaction must be parsed once, attributed to one signer on one chain, charged once, and either commit or refund consistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Construct transactions where signer, predecessor, and relayer identities vary, then assert all value movement and rewards follow the intended identity only. write a Rust integration test that submits crafted raw transaction bytes through `submit()` and asserts sender balance, relayer reward, nonce, logs, and post-state remain consistent
