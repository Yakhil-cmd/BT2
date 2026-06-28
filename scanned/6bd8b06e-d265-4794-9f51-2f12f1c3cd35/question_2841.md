# Q2841: XCC callbacks and router versioning private-call bypass at router code version writes in `set_code_version_of_address`

## Question
Can an unprivileged attacker directly invoke or otherwise spoof the private async context expected by router code version writes in `set_code_version_of_address` through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously, so router, callback, or wNEAR-moving logic runs out of context and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router code version writes in `set_code_version_of_address``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: treat the targeted XCC helper as attacker-callable and check whether context checks fully prevent misuse.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Directly call the function with crafted args and compare behavior to the legitimate async path before and after promise completion. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
