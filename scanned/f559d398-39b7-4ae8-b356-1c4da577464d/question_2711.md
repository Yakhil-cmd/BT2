# Q2711: fund_xcc_sub_account() owner/public split around router code-version assumptions for newly funded accounts

## Question
Can an attacker exploit a public branch in `fund_xcc_sub_account()` on the Aurora engine contract that is safe only when the owner chooses certain defaults, so router code-version assumptions for newly funded accounts still reaches privileged-looking XCC behavior and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/xcc.rs::fund_xcc_sub_account -> engine/src/xcc.rs::fund_xcc_sub_account` -> `router code-version assumptions for newly funded accounts`
- Entrypoint: `fund_xcc_sub_account()` on the Aurora engine contract
- Attacker controls: borsh `FundXccArgs`, target EVM address, optional `wnear_account_id`, attached gas, and repeated funding timing
- Exploit idea: use the public branch to reach the same destination the owner-only branch was expected to guard.
- Invariant to test: XCC sub-account funding must create or top up only the intended router account, with the intended wNEAR source and no stranded or duplicate value
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare owner and public variants of the same flow and assert public callers cannot mutate the same protected router or funding state. write integration tests that call `fund_xcc_sub_account()` with and without `wnear_account_id`, then inspect the created promises, router naming, and value routing
