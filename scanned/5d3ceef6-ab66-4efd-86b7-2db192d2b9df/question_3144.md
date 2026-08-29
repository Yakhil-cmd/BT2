# Q3144: insert via collateral-remove-redeem: push a third party's position past a fold bound so every e

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls `min-underlying` reach `insert` (mainnet/contracts/market/v0-market-vault.clar:159) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it rewrites the whole registry entry for a user id, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:159` -> `insert`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `min-underlying`
- Exploit idea: `insert` rewrites the whole registry entry for a user id. Reach it through `collateral-remove-redeem` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `min-underlying` across its boundary values through `collateral-remove-redeem` in simnet and assert `insert` never returns a value that breaks the invariant.
