# Q1681: ETH connector withdraw serialization split around amount forwarding into the downstream `engine_withdraw` promise

## Question
Can an unprivileged attacker use `withdraw()` on the Aurora engine contract with borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering and make amount forwarding into the downstream `engine_withdraw` promise serialize one recipient, amount, or account identity while the downstream promise or engine path interprets another, leading to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `amount forwarding into the downstream `engine_withdraw` promise`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: abuse a serialization boundary at the targeted step to split what the user intended from what the downstream connector sees.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Inspect the exact promise payload or downstream calldata created from the crafted input and compare it with the original user intent. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
