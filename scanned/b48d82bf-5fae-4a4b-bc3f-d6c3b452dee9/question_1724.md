# Q1724: ETH connector withdraw callback spoof around attached gas computation in `calculate_attached_gas`

## Question
Can an attacker directly invoke or spoof the async context expected by attached gas computation in `calculate_attached_gas` through `withdraw()` on the Aurora engine contract so a callback-only step runs with attacker-controlled bytes and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `attached gas computation in `calculate_attached_gas``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: treat the targeted function as if an attacker can call it out of context and check whether private-call or promise-result assumptions fully hold.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Call the callback entry directly from tests with crafted input and compare behavior to the legitimate promise path. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
