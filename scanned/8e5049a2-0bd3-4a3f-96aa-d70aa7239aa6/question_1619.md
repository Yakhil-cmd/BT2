# Q1619: ETH connector withdraw silo bypass through one-yocto gating before withdrawal

## Question
Can an attacker use `withdraw()` on the Aurora engine contract so that one-yocto gating before withdrawal reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `one-yocto gating before withdrawal`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
