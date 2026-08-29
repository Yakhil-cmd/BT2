# Q3348: resolve via collateral-remove: reprice every other holder's collateral in the same transa

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls the `ft` trait principal reach `resolve` (mainnet/contracts/registry/v0-egroup.clar:360) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it selects the efficiency group for a position mask, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:360` -> `resolve`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `resolve` selects the efficiency group for a position mask. Reach it through `collateral-remove` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the `ft` trait principal across its boundary values through `collateral-remove` in simnet and assert `resolve` never returns a value that breaks the invariant.
