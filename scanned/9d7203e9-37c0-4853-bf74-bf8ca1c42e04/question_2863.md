# Q2863: XCC callbacks and router versioning sub-account mixup in router bytecode storage in `update_router_code`

## Question
Can an attacker choose inputs through public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously that make router bytecode storage in `update_router_code` derive, fund, or withdraw to the wrong XCC sub-account, so value or code ends up bound to the wrong owner and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::withdraw_wnear_to_router / factory_update_address_version + engine/src/xcc.rs` -> `router bytecode storage in `update_router_code``
- Entrypoint: public invocation attempts against `withdraw_wnear_to_router()` or `factory_update_address_version()`, plus user flows that trigger them asynchronously
- Attacker controls: direct callback invocation attempts, borsh callback args, promise success/failure timing, target address bytes, and router-version update ordering
- Exploit idea: attack address-to-subaccount derivation or recipient formatting at the XCC layer.
- Invariant to test: private XCC callbacks must only run in the intended async context and must not desynchronize router code version, recipient routing, or wNEAR movement
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Generate edge-case target addresses and assert the derived sub-account and routed value always match the intended EVM owner. write tests that directly invoke both callbacks and also reach them through the intended promise path, then compare version state, balances, and emitted promises
