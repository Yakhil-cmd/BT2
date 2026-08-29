# Q1516: get-account-scaled-debt via liquidate-multi: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the full batch list and its ordering reach `get-account-scaled-debt` (mainnet/contracts/market/v0-market-vault.clar:307) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it reads one scaled debt row, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:307` -> `get-account-scaled-debt`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the full batch list and its ordering
- Exploit idea: `get-account-scaled-debt` reads one scaled debt row. Reach it through `liquidate-multi` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `liquidate-multi` with the full batch list and its ordering, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
