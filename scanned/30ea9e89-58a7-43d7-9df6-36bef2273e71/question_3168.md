# Q3168: convert-to-scaled-debt via collateral-add: seize from a position that is solvent under the mask its o

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls the three `price-feeds` buffers and their order reach `convert-to-scaled-debt` (mainnet/contracts/market/v0-4-market.clar:648) in a state where it seize from a position that is solvent under the mask its own operations were validated against? Given that it scales a token amount by the cached borrow index, rounding up on the borrow path, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:648` -> `convert-to-scaled-debt`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the three `price-feeds` buffers and their order
- Exploit idea: `convert-to-scaled-debt` scales a token amount by the cached borrow index, rounding up on the borrow path. Reach it through `collateral-add` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the three `price-feeds` buffers and their order across its boundary values through `collateral-add` in simnet and assert `convert-to-scaled-debt` never returns a value that breaks the invariant.
