# Q2209: write-feeds via collateral-add: prime shared state so the next caller in the block is eval

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling the three `price-feeds` buffers and their order, drive `write-feeds` (mainnet/contracts/market/v0-4-market.clar:149) — which folds up to three attacker-supplied buffers through `write-feed` with a `(response bool uint)` accumulator — to prime shared state so the next caller in the block is evaluated against it, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:149` -> `write-feeds`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the three `price-feeds` buffers and their order
- Exploit idea: `write-feeds` folds up to three attacker-supplied buffers through `write-feed` with a `(response bool uint)` accumulator. Reach it through `collateral-add` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-add` with the three `price-feeds` buffers and their order, then read `write-feeds` state before and after in the same block and assert the two sides of the invariant are equal.
