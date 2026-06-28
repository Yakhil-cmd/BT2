# Q2758: XCC callbacks and router versioning unfunded success signal from failed-promise rejection via `promise_result_check()`

## Question
Can an attacker make failed-promise rejection via `promise_result_check()` signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
