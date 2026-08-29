# Q4009: resolve via collateral-add: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling whether this asset is already collateral (the is-new-collateral branch), drive `resolve` (mainnet/contracts/registry/v0-egroup.clar:360) — which selects the efficiency group for a position mask — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:360` -> `resolve`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: whether this asset is already collateral (the is-new-collateral branch)
- Exploit idea: `resolve` selects the efficiency group for a position mask. Reach it through `collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-add` with whether this asset is already collateral (the is-new-collateral branch), then read `resolve` state before and after in the same block and assert the two sides of the invariant are equal.
