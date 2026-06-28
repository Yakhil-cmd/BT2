# Q2745: XCC callbacks and router versioning promise graph underfunding at failed-promise rejection via `promise_result_check()`

## Question
Can an attacker make failed-promise rejection via `promise_result_check()` construct an underfunded or incomplete promise graph through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so the public action reaches an unrecoverable half-complete state and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: starve the XCC promise graph of gas or required state after the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Vary prepaid gas and callback complexity around the targeted path and assert either full completion or a safe rollback/refund outcome. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
