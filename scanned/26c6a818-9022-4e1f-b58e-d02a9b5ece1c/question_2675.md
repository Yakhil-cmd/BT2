# Q2675: fund_xcc_sub_account() state commit before safety check at attached gas sizing for the resulting promise graph

## Question
Can an attacker make attached gas sizing for the resulting promise graph write state or consume value before the final safety check that should have rejected the flow, leaving an exploitable partial commit that causes Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `attached gas sizing for the resulting promise graph`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for XCC state writes or value consumption before the last rejecting condition in the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Trigger the last failing condition after the targeted write and assert nothing persistent remains. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
