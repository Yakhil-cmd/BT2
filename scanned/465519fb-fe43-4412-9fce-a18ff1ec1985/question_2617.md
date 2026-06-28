# Q2617: fund_xcc_sub_account() router account collision at sub-account naming and address encoding in XCC

## Question
Can an attacker choose inputs through `fund_xcc_sub_account()` on the Aurora engine contract that make sub-account naming and address encoding in XCC collide two logically separate router accounts or overwrite one user’s XCC routing with another’s, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `sub-account naming and address encoding in XCC`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: target uniqueness assumptions for router sub-account naming or address mapping.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Search for collisions under fuzzed addresses and ensure every generated router account remains unique and stable. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
