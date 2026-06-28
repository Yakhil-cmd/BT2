# Q2673: fund_xcc_sub_account() async order dependence in attached gas sizing for the resulting promise graph

## Question
Can an attacker exploit asynchronous ordering around attached gas sizing for the resulting promise graph so that two legitimate XCC flows complete in the wrong order and one overwrites or steals the other’s value or metadata, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `attached gas sizing for the resulting promise graph`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: target ordering assumptions between multiple in-flight XCC operations touching the same state.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Launch concurrent flows against the same address or sub-account and vary callback order while asserting final value and version state stay serializable. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
