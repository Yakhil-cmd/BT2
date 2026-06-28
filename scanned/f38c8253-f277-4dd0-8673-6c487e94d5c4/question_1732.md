# Q1732: ETH connector withdraw mapping collision around attached gas computation in `calculate_attached_gas`

## Question
Can an attacker choose inputs through `withdraw()` on the Aurora engine contract so that attached gas computation in `calculate_attached_gas` collides two distinct users, assets, or registrations into one storage key or one effective route, causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `attached gas computation in `calculate_attached_gas``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: target the storage key or mapping derivation consumed by the named step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Search for colliding identifiers under fuzzed account and asset inputs and assert the contract always preserves one-to-one mappings. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
