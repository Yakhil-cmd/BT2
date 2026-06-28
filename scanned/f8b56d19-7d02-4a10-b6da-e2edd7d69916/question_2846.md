# Q2846: XCC callbacks and router versioning callback result confusion in router code version writes in `set_code_version_of_address`

## Question
Can an attacker cause router code version writes in `set_code_version_of_address` to trust the wrong promise result or promise position through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so it moves value or updates router state based on unrelated async output and causes Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router code version writes in `set_code_version_of_address``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: target result-index or result-success assumptions in the XCC callback.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Mock alternate promise result counts and orderings and assert the callback rejects every layout except the exact intended one. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
