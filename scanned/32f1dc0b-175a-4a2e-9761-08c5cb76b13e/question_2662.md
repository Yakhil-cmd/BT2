# Q2662: fund_xcc_sub_account() router version desync around attached gas sizing for the resulting promise graph

## Question
Can an attacker use `fund_xcc_sub_account()` on the Aurora engine contract so that attached gas sizing for the resulting promise graph updates router code, version, or address metadata without the matching deployment or funding state actually succeeding, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `attached gas sizing for the resulting promise graph`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: split router metadata writes from the real deployment/funding success condition.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cause deployment or funding failure after the targeted step and assert stored version/address state remains unchanged. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
