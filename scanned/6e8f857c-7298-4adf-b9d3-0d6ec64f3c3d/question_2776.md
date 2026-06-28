# Q2776: XCC callbacks and router versioning router bytecode confusion around recipient sub-account formatting from `args.target.encode()`

## Question
Can an attacker influence which router bytecode or code-version assumption recipient sub-account formatting from `args.target.encode()` uses for a live user flow through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so the wrong router behavior receives funds and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `recipient sub-account formatting from `args.target.encode()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: split bytecode selection from address/version selection near the targeted helper.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Capture the code hash selected for the flow and verify it always matches the stored version and intended deployment outcome. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
