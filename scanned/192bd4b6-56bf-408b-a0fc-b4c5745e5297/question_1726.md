# Q1726: ETH connector withdraw duplicate registration through attached gas computation in `calculate_attached_gas`

## Question
Can an attacker use `withdraw()` on the Aurora engine contract so that attached gas computation in `calculate_attached_gas` registers the same asset, account, or mapping twice under inconsistent metadata or addresses, breaking canonical mapping invariants and causing Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `attached gas computation in `calculate_attached_gas``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: create a duplicate or conflicting registration state around the targeted helper.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Insolvency
- Fast validation: Attempt repeated registration and mixed metadata paths, then assert the canonical mapping stays one-to-one and balances remain intact. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
