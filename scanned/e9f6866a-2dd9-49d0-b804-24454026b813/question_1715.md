# Q1715: ETH connector withdraw private or owner split at connector account lookup in `return_promise`

## Question
Can an attacker exploit the 'private or owner' assumption around connector account lookup in `return_promise` through `withdraw()` on the Aurora engine contract, so a public call mimics an internal path and mutates protected configuration or value-bearing state, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `connector account lookup in `return_promise``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: test whether the targeted branch really distinguishes private callbacks from external calls in all cases.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Call the method from both the intended internal path and a direct external path and compare authorization behavior before any mutation. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
