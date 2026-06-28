# Q2575: fund_xcc_sub_account() state commit before safety check at public-versus-owner branch when `wnear_account_id` is `None` or `Some`

## Question
Can an attacker make public-versus-owner branch when `wnear_account_id` is `None` or `Some` write state or consume value before the final safety check that should have rejected the flow, leaving an exploitable partial commit that causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `public-versus-owner branch when `wnear_account_id` is `None` or `Some``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for XCC state writes or value consumption before the last rejecting condition in the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Trigger the last failing condition after the targeted write and assert nothing persistent remains. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
