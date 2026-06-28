# Q2646: fund_xcc_sub_account() callback result confusion in router deployment funding logic

## Question
Can an attacker cause router deployment funding logic to trust the wrong promise result or promise position through `fund_xcc_sub_account()` on the Aurora engine contract, so it moves value or updates router state based on unrelated async output and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router deployment funding logic`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: target result-index or result-success assumptions in the XCC callback.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Mock alternate promise result counts and orderings and assert the callback rejects every layout except the exact intended one. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
