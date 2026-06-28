# Q1690: ETH connector withdraw amount scale split around amount forwarding into the downstream `engine_withdraw` promise

## Question
Can an attacker force amount forwarding into the downstream `engine_withdraw` promise to interpret the same amount under two different units, decimal conventions, or byte widths through `withdraw()` on the Aurora engine contract, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `amount forwarding into the downstream `engine_withdraw` promise`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: attack amount scaling and numeric width at the named connector boundary.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Fuzz amount boundaries and compare the public amount with the actual burned, minted, transferred, or refunded amount. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
