# Q2836: XCC callbacks and router versioning router bytecode confusion around successful-deploy gating before router version writes

## Question
Can an attacker influence which router bytecode or code-version assumption successful-deploy gating before router version writes uses for a live user flow through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so the wrong router behavior receives funds and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `successful-deploy gating before router version writes`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: split bytecode selection from address/version selection near the targeted helper.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Capture the code hash selected for the flow and verify it always matches the stored version and intended deployment outcome. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
