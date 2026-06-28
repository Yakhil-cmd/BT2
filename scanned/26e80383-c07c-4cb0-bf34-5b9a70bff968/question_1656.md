# Q1656: ETH connector withdraw queue or promise stranding at construction of `EngineWithdrawCallArgs`

## Question
Can an attacker make construction of `EngineWithdrawCallArgs` enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `construction of `EngineWithdrawCallArgs``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
