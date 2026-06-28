# Q2710: fund_xcc_sub_account() address encoding edge in router code-version assumptions for newly funded accounts

## Question
Can an attacker use edge-case address encodings through `fund_xcc_sub_account()` on the Aurora engine contract so that router code-version assumptions for newly funded accounts truncates, collides, or reformats the target differently from later consumers, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router code-version assumptions for newly funded accounts`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: attack address encoding and formatting at the targeted XCC boundary.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Fuzz edge-case EVM addresses and compare the encoded address used in every downstream promise and stored metadata field. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
