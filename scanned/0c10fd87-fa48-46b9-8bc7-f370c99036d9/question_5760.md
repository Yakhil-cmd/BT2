# Q5760: population via collateral-remove: prime shared state so the next caller in the block is eval

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls the `price-feeds` buffers reach `population` (mainnet/contracts/registry/v0-egroup.clar:81) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it counts set bits to order the bucket search, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:81` -> `population`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the `price-feeds` buffers
- Exploit idea: `population` counts set bits to order the bucket search. Reach it through `collateral-remove` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the `price-feeds` buffers across its boundary values through `collateral-remove` in simnet and assert `population` never returns a value that breaks the invariant.
