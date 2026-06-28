# Q2788: XCC callbacks and router versioning code/address split at wNEAR address lookup from precompile state

## Question
Can an attacker cause wNEAR address lookup from precompile state to pair router code from one version with address metadata from another through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so later calls use mismatched code and value-routing assumptions and lead to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `wNEAR address lookup from precompile state`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: desynchronize the code-version and address-version state touched by the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Update or fail the code path around the targeted callback and assert the stored version and deployed code hash remain in lockstep. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
