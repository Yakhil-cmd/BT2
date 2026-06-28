# Q2813: XCC callbacks and router versioning async order dependence in private-call enforcement in `factory_update_address_version`

## Question
Can an attacker exploit asynchronous ordering around private-call enforcement in `factory_update_address_version` so that two legitimate XCC flows complete in the wrong order and one overwrites or steals the other’s value or metadata, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `private-call enforcement in `factory_update_address_version``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: target ordering assumptions between multiple in-flight XCC operations touching the same state.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Launch concurrent flows against the same address or sub-account and vary callback order while asserting final value and version state stay serializable. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
