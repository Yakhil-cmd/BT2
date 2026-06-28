# Q2691: fund_xcc_sub_account() owner/public split around storage staking assumptions for first-use account creation

## Question
Can an attacker exploit a public branch in `fund_xcc_sub_account()` on the Aurora engine contract that is safe only when the owner chooses certain defaults, so storage staking assumptions for first-use account creation still reaches privileged-looking XCC behavior and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `storage staking assumptions for first-use account creation`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: use the public branch to reach the same destination the owner-only branch was expected to guard.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Compare owner and public variants of the same flow and assert public callers cannot mutate the same protected router or funding state. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
