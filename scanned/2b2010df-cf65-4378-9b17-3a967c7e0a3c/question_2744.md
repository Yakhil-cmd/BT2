# Q2744: XCC callbacks and router versioning wNEAR source confusion around failed-promise rejection via `promise_result_check()`

## Question
Can an attacker use public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously to make failed-promise rejection via `promise_result_check()` unwrap, fund, or refund using the wrong wNEAR source or amount source, leading to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: misroute wNEAR source selection at the targeted funding or withdraw step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Track which address loses wNEAR and which router/sub-account gains NEAR under crafted inputs and failure branches. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
