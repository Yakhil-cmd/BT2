# Q1720: ETH connector withdraw resource exhaustion seeded by connector account lookup in `return_promise`

## Question
Can an attacker use `withdraw()` on the Aurora engine contract so that connector account lookup in `return_promise` keeps creating state, promises, or registrations that the protocol must later pay to maintain, eventually causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::withdraw` -> `connector account lookup in `return_promise``
- Entrypoint: `withdraw()` on the Aurora engine contract
- Attacker controls: borsh `WithdrawCallArgs`, recipient address bytes, withdraw amount, attached 1 yocto, and repeated withdraw ordering
- Exploit idea: look for unbounded public resource creation rooted in the targeted connector step.
- Invariant to test: connector withdrawals must serialize the intended recipient and amount exactly once and must not burn, route, or refund value inconsistently
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run a high-count local sequence and measure whether protocol-held storage, registration state, or required connector balance grows without safe user-paid bounds. write integration tests that call `withdraw()` with crafted recipient encodings and amounts, then inspect the promise payload and resulting Aurora-side balances
