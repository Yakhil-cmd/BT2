# Q2811: XCC callbacks and router versioning owner/public split around private-call enforcement in `factory_update_address_version`

## Question
Can an attacker exploit a public branch in public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously that is safe only when the owner chooses certain defaults, so private-call enforcement in `factory_update_address_version` still reaches privileged-looking XCC behavior and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `private-call enforcement in `factory_update_address_version``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: use the public branch to reach the same destination the owner-only branch was expected to guard.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Compare owner and public variants of the same flow and assert public callers cannot mutate the same protected router or funding state. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
