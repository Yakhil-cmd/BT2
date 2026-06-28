# Q2700: fund_xcc_sub_account() refund-less failure around storage staking assumptions for first-use account creation

## Question
Can an attacker make storage staking assumptions for first-use account creation fail after user value has been consumed but before any refund path becomes reachable, producing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `storage staking assumptions for first-use account creation`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: seek a failure mode where the targeted XCC step consumes value without arming compensation logic.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Cause failures at every downstream branch after the targeted step and assert user value is always restored or safely progressed. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
