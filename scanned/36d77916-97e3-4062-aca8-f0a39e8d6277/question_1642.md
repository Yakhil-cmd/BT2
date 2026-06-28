# Q1642: ETH connector withdraw double-apply path at construction of `EngineWithdrawCallArgs`

## Question
Can an attacker trigger construction of `EngineWithdrawCallArgs` twice for one logical action through retries, repeated calls, or callback reuse from `withdraw()` on the Aurora engine contract, so burn, mint, refund, or registration state is applied more than once and causes Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `construction of `EngineWithdrawCallArgs``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: look for a one-to-many application of one user action around the targeted connector step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Replay the same logical action across repeated calls and callback timing variations and assert supply, mappings, and balances remain single-applied. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
