# Q2664: fund_xcc_sub_account() wNEAR source confusion around attached gas sizing for the resulting promise graph

## Question
Can an attacker use `fund_xcc_sub_account()` on the Aurora engine contract to make attached gas sizing for the resulting promise graph unwrap, fund, or refund using the wrong wNEAR source or amount source, leading to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `attached gas sizing for the resulting promise graph`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: misroute wNEAR source selection at the targeted funding or withdraw step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Track which address loses wNEAR and which router/sub-account gains NEAR under crafted inputs and failure branches. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
