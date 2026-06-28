# Q2639: fund_xcc_sub_account() shared state overwrite via wNEAR source-account selection

## Question
Can an attacker use `fund_xcc_sub_account()` on the Aurora engine contract to make wNEAR source-account selection overwrite shared XCC state that another in-flight operation still depends on, resulting in stranded or stolen value and Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `wNEAR source-account selection`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for non-namespaced XCC state touched by multiple public flows.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run overlapping operations against shared state and assert their metadata and balances do not overwrite each other. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
