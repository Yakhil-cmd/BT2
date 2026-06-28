# Q2778: XCC callbacks and router versioning unfunded success signal from recipient sub-account formatting from `args.target.encode()`

## Question
Can an attacker make recipient sub-account formatting from `args.target.encode()` signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `recipient sub-account formatting from `args.target.encode()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
