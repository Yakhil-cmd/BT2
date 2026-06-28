# Q1693: ETH connector withdraw rollback gap after amount forwarding into the downstream `engine_withdraw` promise

## Question
Can an attacker make amount forwarding into the downstream `engine_withdraw` promise mutate state or emit a promise before a later failing step aborts the public call, leaving a rollback gap that can be exploited for Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `amount forwarding into the downstream `engine_withdraw` promise`
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: force a failure immediately after the named connector mutation or promise creation.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Cause the downstream step to fail and verify all earlier state, supply, and mapping changes are either rolled back or safely compensated. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
