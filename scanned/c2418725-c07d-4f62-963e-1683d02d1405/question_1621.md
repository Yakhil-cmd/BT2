# Q1621: ETH connector withdraw serialization split around borsh parsing of `WithdrawCallArgs`

## Question
Can an unprivileged attacker use `withdraw()` on the Aurora engine contract with borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering and make borsh parsing of `WithdrawCallArgs` serialize one recipient, amount, or account identity while the downstream promise or engine path interprets another, leading to Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `borsh parsing of `WithdrawCallArgs``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: abuse a serialization boundary at the targeted step to split what the user intended from what the downstream connector sees.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Inspect the exact promise payload or downstream calldata created from the crafted input and compare it with the original user intent. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
