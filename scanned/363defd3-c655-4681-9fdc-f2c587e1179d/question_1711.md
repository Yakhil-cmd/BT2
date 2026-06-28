# Q1711: ETH connector withdraw idempotence break at connector account lookup in `return_promise`

## Question
Can an attacker repeat the exact same public request through `withdraw()` on the Aurora engine contract and make connector account lookup in `return_promise` treat it as fresh instead of already-consumed state, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `connector account lookup in `return_promise``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: look for missing idempotence or replay resistance at the targeted connector step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Replay the same request and assert supply, storage registration, and mappings do not move on the second attempt. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
