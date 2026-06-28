# Q2827: XCC callbacks and router versioning replayable funding around successful-deploy gating before router version writes

## Question
Can an attacker replay a funding or withdraw-intent through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously so successful-deploy gating before router version writes processes the same logical XCC action more than once, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `successful-deploy gating before router version writes`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for missing idempotence around router funding or async withdraw settlement.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Replay the same funding intent under identical and reordered conditions and compare router balance, version state, and user balances. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
