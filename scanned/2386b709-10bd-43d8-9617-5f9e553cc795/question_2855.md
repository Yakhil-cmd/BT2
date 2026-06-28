# Q2855: XCC callbacks and router versioning state commit before safety check at router code version writes in `set_code_version_of_address`

## Question
Can an attacker make router code version writes in `set_code_version_of_address` write state or consume value before the final safety check that should have rejected the flow, leaving an exploitable partial commit that causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router code version writes in `set_code_version_of_address``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: look for XCC state writes or value consumption before the last rejecting condition in the targeted step.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Trigger the last failing condition after the targeted write and assert nothing persistent remains. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
