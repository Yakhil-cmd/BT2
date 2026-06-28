# Q2852: XCC callbacks and router versioning retry recovery gap at router code version writes in `set_code_version_of_address`

## Question
Can an attacker push router code version writes in `set_code_version_of_address` into a failure state that cannot be retried safely but also does not restore consumed funds or metadata, leaving recoverability broken and causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router code version writes in `set_code_version_of_address``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: force the targeted step into a non-idempotent failed state.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Cause failure before and after the targeted mutation and verify every failed state has one safe retry or full refund path. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
