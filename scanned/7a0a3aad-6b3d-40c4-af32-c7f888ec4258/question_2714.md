# Q2714: fund_xcc_sub_account() router migration gap through router code-version assumptions for newly funded accounts

## Question
Can an attacker exploit an update or migration boundary around router code-version assumptions for newly funded accounts so old router assumptions and new router assumptions coexist long enough to misroute value and cause Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router code-version assumptions for newly funded accounts`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: attack router version transition semantics at the targeted step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Exercise the flow during a version change and compare behavior before, during, and after the update to ensure no mixed-version state is accepted. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
