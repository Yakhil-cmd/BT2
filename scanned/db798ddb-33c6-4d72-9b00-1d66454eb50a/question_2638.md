# Q2638: fund_xcc_sub_account() unfunded success signal from wNEAR source-account selection

## Question
Can an attacker make wNEAR source-account selection signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `wNEAR source-account selection`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
