# Q2685: fund_xcc_sub_account() promise graph underfunding at storage staking assumptions for first-use account creation

## Question
Can an attacker make storage staking assumptions for first-use account creation construct an underfunded or incomplete promise graph through `fund_xcc_sub_account()` on the Aurora engine contract, so the public action reaches an unrecoverable half-complete state and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `storage staking assumptions for first-use account creation`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: starve the XCC promise graph of gas or required state after the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Vary prepaid gas and callback complexity around the targeted path and assert either full completion or a safe rollback/refund outcome. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
