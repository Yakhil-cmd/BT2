# Q2762: XCC callbacks and router versioning router version desync around recipient sub-account formatting from `args.target.encode()`

## Question
Can an attacker use public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously so that recipient sub-account formatting from `args.target.encode()` updates router code, version, or address metadata without the matching deployment or funding state actually succeeding, leading to Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `recipient sub-account formatting from `args.target.encode()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: split router metadata writes from the real deployment/funding success condition.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Cause deployment or funding failure after the targeted step and assert stored version/address state remains unchanged. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
