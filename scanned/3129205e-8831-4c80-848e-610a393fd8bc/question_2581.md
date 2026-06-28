# Q2581: fund_xcc_sub_account() private-call bypass at borsh decoding of `FundXccArgs`

## Question
Can an unprivileged attacker directly invoke or otherwise spoof the private async context expected by borsh decoding of `FundXccArgs` through `fund_xcc_sub_account()` on the Aurora engine contract, so router, callback, or wNEAR-moving logic runs out of context and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `borsh decoding of `FundXccArgs``
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: treat the targeted XCC helper as attacker-callable and check whether context checks fully prevent misuse.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Directly call the function with crafted args and compare behavior to the legitimate async path before and after promise completion. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
