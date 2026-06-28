# Q2849: XCC callbacks and router versioning funding shortfall after router code version writes in `set_code_version_of_address`

## Question
Can an attacker make router code version writes in `set_code_version_of_address` consume user value to start an XCC flow but leave the resulting router account underfunded for completion or recovery, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router code version writes in `set_code_version_of_address``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: strand value by separating initial funding from the minimum viable router balance.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Measure router balance after partial funding and ensure every accepted path leaves enough balance either to complete or to refund safely. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
