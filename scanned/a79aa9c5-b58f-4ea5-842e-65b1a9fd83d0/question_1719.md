# Q1719: ETH connector withdraw silo bypass through connector account lookup in `return_promise`

## Question
Can an attacker use `withdraw()` on the Aurora engine contract so that connector account lookup in `return_promise` reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `connector account lookup in `return_promise``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
