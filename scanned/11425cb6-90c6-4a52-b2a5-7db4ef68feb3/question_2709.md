# Q2709: fund_xcc_sub_account() funding shortfall after router code-version assumptions for newly funded accounts

## Question
Can an attacker make router code-version assumptions for newly funded accounts consume user value to start an XCC flow but leave the resulting router account underfunded for completion or recovery, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router code-version assumptions for newly funded accounts`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: strand value by separating initial funding from the minimum viable router balance.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Measure router balance after partial funding and ensure every accepted path leaves enough balance either to complete or to refund safely. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
