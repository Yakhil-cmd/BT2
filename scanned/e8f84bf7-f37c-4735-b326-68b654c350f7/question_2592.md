# Q2592: fund_xcc_sub_account() retry recovery gap at borsh decoding of `FundXccArgs`

## Question
Can an attacker push borsh decoding of `FundXccArgs` into a failure state that cannot be retried safely but also does not restore consumed funds or metadata, leaving recoverability broken and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `borsh decoding of `FundXccArgs``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: force the targeted step into a non-idempotent failed state.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Cause failure before and after the targeted mutation and verify every failed state has one safe retry or full refund path. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
