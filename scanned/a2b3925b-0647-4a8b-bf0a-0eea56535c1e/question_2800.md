# Q2800: XCC callbacks and router versioning refund-less failure around wNEAR address lookup from precompile state

## Question
Can an attacker make wNEAR address lookup from precompile state fail after user value has been consumed but before any refund path becomes reachable, producing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `wNEAR address lookup from precompile state`
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: seek a failure mode where the targeted XCC step consumes value without arming compensation logic.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cause failures at every downstream branch after the targeted step and assert user value is always restored or safely progressed. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
