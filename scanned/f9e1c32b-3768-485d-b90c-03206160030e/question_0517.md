# Q0517: insert via collateral-add: push a third party's position past a fold bound so every e

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling the `ft` trait principal, drive `insert` (mainnet/contracts/market/v0-market-vault.clar:159) — which rewrites the whole registry entry for a user id — to push a third party's position past a fold bound so every evaluation of it aborts, breaking the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:159` -> `insert`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `insert` rewrites the whole registry entry for a user id. Reach it through `collateral-add` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-add` with the `ft` trait principal, then read `insert` state before and after in the same block and assert the two sides of the invariant are equal.
