# Q2587: fund_xcc_sub_account() replayable funding around borsh decoding of `FundXccArgs`

## Question
Can an attacker replay a funding or withdraw-intent through `fund_xcc_sub_account()` on the Aurora engine contract so borsh decoding of `FundXccArgs` processes the same logical XCC action more than once, causing Smart contract unable to operate due to lack of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `borsh decoding of `FundXccArgs``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: look for missing idempotence around router funding or async withdraw settlement.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Smart contract unable to operate due to lack of funds
- Fast validation: Replay the same funding intent under identical and reordered conditions and compare router balance, version state, and user balances. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
