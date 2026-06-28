# Q2828: XCC callbacks and router versioning code/address split at successful-deploy gating before router version writes

## Question
Can an attacker cause successful-deploy gating before router version writes to pair router code from one version with address metadata from another through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so later calls use mismatched code and value-routing assumptions and lead to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `successful-deploy gating before router version writes`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: desynchronize the code-version and address-version state touched by the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Update or fail the code path around the targeted callback and assert the stored version and deployed code hash remain in lockstep. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
