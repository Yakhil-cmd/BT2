# Q4063: subset via borrow: prime shared state so the next caller in the block is eval

## Question
`subset` (mainnet/contracts/market/v0-market-vault.clar:100) tests bitmask containment. Can an unprivileged caller of `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), by choosing the future mask produced by the new debt bit, use that to prime shared state so the next caller in the block is evaluated against it, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:100` -> `subset`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `subset` tests bitmask containment. Reach it through `borrow` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `borrow` with the future mask produced by the new debt bit, then read `subset` state before and after in the same block and assert the two sides of the invariant are equal.
