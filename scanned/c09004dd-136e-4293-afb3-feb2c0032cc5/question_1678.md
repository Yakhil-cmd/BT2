# Q1678: ETH connector withdraw revert/success split after recipient address serialization for the downstream connector

## Question
Can an attacker make recipient address serialization for the downstream connector treat a downstream revert as success, or a downstream success as failure, so mint, refund, or registration logic goes down the wrong branch and leads to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `recipient address serialization for the downstream connector`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: attack success detection and branch selection around the targeted callback or promise result.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Simulate both success and failure promise outcomes and assert the chosen branch matches the real downstream result every time. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
