# Q2578: fund_xcc_sub_account() unfunded success signal from public-versus-owner branch when `wnear_account_id` is `None` or `Some`

## Question
Can an attacker make public-versus-owner branch when `wnear_account_id` is `None` or `Some` signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `public-versus-owner branch when `wnear_account_id` is `None` or `Some``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
