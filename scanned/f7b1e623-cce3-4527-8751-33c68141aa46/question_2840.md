# Q2840: XCC callbacks and router versioning refund-less failure around successful-deploy gating before router version writes

## Question
Can an attacker make successful-deploy gating before router version writes fail after user value has been consumed but before any refund path becomes reachable, producing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `successful-deploy gating before router version writes`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: seek a failure mode where the targeted XCC step consumes value without arming compensation logic.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Cause failures at every downstream branch after the targeted step and assert user value is always restored or safely progressed. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
