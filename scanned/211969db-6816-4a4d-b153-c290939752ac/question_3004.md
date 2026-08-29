# Q3004: check-confidence via supply-collateral-add: push a third party's position past a fold bound so every e

## Question
Does `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175) let an unprivileged attacker who controls `min-shares` (the only slippage bound on the deposit leg) reach `check-confidence` (mainnet/contracts/market/v0-4-market.clar:305) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it compares the Pyth confidence interval against `max-confidence-ratio` in BPS, a gate that has no DIA equivalent, the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements breaks and the result is direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:305` -> `check-confidence`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: `min-shares` (the only slippage bound on the deposit leg)
- Exploit idea: `check-confidence` compares the Pyth confidence interval against `max-confidence-ratio` in BPS, a gate that has no DIA equivalent. Reach it through `supply-collateral-add` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `supply-collateral-add` with `min-shares` (the only slippage bound on the deposit leg), and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
