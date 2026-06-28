# Q2588: fund_xcc_sub_account() code/address split at borsh decoding of `FundXccArgs`

## Question
Can an attacker cause borsh decoding of `FundXccArgs` to pair router code from one version with address metadata from another through `fund_xcc_sub_account()` on the Aurora engine contract, so later calls use mismatched code and value-routing assumptions and lead to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `borsh decoding of `FundXccArgs``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: desynchronize the code-version and address-version state touched by the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Update or fail the code path around the targeted callback and assert the stored version and deployed code hash remain in lockstep. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
