# Q2818: XCC callbacks and router versioning unfunded success signal from private-call enforcement in `factory_update_address_version`

## Question
Can an attacker make private-call enforcement in `factory_update_address_version` signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `private-call enforcement in `factory_update_address_version``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
