# Q2750: XCC callbacks and router versioning address encoding edge in failed-promise rejection via `promise_result_check()`

## Question
Can an attacker use edge-case address encodings through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously so that failed-promise rejection via `promise_result_check()` truncates, collides, or reformats the target differently from later consumers, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `failed-promise rejection via `promise_result_check()``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: attack address encoding and formatting at the targeted XCC boundary.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Fuzz edge-case EVM addresses and compare the encoded address used in every downstream promise and stored metadata field. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
