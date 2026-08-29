# Q0994: insert via collateral-remove: route a victim's mandatory payout through a principal that

## Question
Entering through `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) while controlling the `price-feeds` buffers, can an unprivileged attacker make `insert` (mainnet/contracts/market/v0-market-vault.clar:159) route a victim's mandatory payout through a principal that always rejects delivery? `insert` rewrites the whole registry entry for a user id, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:159` -> `insert`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the `price-feeds` buffers
- Exploit idea: `insert` rewrites the whole registry entry for a user id. Reach it through `collateral-remove` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `collateral-remove` with the `price-feeds` buffers, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
