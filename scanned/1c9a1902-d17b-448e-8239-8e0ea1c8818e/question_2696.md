# Q2696: fund_xcc_sub_account() router bytecode confusion around storage staking assumptions for first-use account creation

## Question
Can an attacker influence which router bytecode or code-version assumption storage staking assumptions for first-use account creation uses for a live user flow through `fund_xcc_sub_account()` on the Aurora engine contract, so the wrong router behavior receives funds and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `storage staking assumptions for first-use account creation`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: split bytecode selection from address/version selection near the targeted helper.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Capture the code hash selected for the flow and verify it always matches the stored version and intended deployment outcome. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
