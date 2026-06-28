# Q2817: XCC callbacks and router versioning router account collision at private-call enforcement in `factory_update_address_version`

## Question
Can an attacker choose inputs through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously that make private-call enforcement in `factory_update_address_version` collide two logically separate router accounts or overwrite one user’s XCC routing with another’s, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `private-call enforcement in `factory_update_address_version``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: target uniqueness assumptions for router sub-account naming or address mapping.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Search for collisions under fuzzed addresses and ensure every generated router account remains unique and stable. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
