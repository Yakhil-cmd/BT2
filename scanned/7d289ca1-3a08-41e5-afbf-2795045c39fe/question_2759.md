# Q2759: XCC callbacks and router versioning shared state overwrite via failed-promise rejection via `promise_result_check()`

## Question
Can an attacker use public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously to make failed-promise rejection via `promise_result_check()` overwrite shared XCC state that another in-flight operation still depends on, resulting in stranded or stolen value and Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for non-namespaced XCC state touched by multiple public flows.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Run overlapping operations against shared state and assert their metadata and balances do not overwrite each other. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
