# Q2604: fund_xcc_sub_account() wNEAR source confusion around sub-account naming and address encoding in XCC

## Question
Can an attacker use `fund_xcc_sub_account()` on the Aurora engine contract to make sub-account naming and address encoding in XCC unwrap, fund, or refund using the wrong wNEAR source or amount source, leading to Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `sub-account naming and address encoding in XCC`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: misroute wNEAR source selection at the targeted funding or withdraw step.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Track which address loses wNEAR and which router/sub-account gains NEAR under crafted inputs and failure branches. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
