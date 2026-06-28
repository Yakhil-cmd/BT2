# Q2754: XCC callbacks and router versioning router migration gap through failed-promise rejection via `promise_result_check()`

## Question
Can an attacker exploit an update or migration boundary around failed-promise rejection via `promise_result_check()` so old router assumptions and new router assumptions coexist long enough to misroute value and cause Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: attack router version transition semantics at the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Exercise the flow during a version change and compare behavior before, during, and after the update to ensure no mixed-version state is accepted. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
