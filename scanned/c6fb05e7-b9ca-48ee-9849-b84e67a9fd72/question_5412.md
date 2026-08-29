# Q5412: insert via collateral-add: reprice every other holder's collateral in the same transa

## Question
Does `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020) let an unprivileged attacker who controls whether this asset is already collateral (the is-new-collateral branch) reach `insert` (mainnet/contracts/market/v0-market-vault.clar:159) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it rewrites the whole registry entry for a user id, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:159` -> `insert`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: whether this asset is already collateral (the is-new-collateral branch)
- Exploit idea: `insert` rewrites the whole registry entry for a user id. Reach it through `collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz whether this asset is already collateral (the is-new-collateral branch) across its boundary values through `collateral-add` in simnet and assert `insert` never returns a value that breaks the invariant.
