# Q2712: fund_xcc_sub_account() retry recovery gap at router code-version assumptions for newly funded accounts

## Question
Can an attacker push router code-version assumptions for newly funded accounts into a failure state that cannot be retried safely but also does not restore consumed funds or metadata, leaving recoverability broken and causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router code-version assumptions for newly funded accounts`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: force the targeted step into a non-idempotent failed state.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Cause failure before and after the targeted mutation and verify every failed state has one safe retry or full refund path. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
