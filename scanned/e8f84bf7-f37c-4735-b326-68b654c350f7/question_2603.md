# Q2603: fund_xcc_sub_account() sub-account mixup in sub-account naming and address encoding in XCC

## Question
Can an attacker choose inputs through `fund_xcc_sub_account()` on the Aurora engine contract that make sub-account naming and address encoding in XCC derive, fund, or withdraw to the wrong XCC sub-account, so value or code ends up bound to the wrong owner and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `sub-account naming and address encoding in XCC`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: attack address-to-subaccount derivation or recipient formatting at the XCC layer.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Generate edge-case target addresses and assert the derived sub-account and routed value always match the intended EVM owner. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
