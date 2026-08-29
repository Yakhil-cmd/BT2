# Q5350: merge-price via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `min-collateral-expected`, can an unprivileged attacker make `merge-price` (mainnet/contracts/market/v0-4-market.clar:506) make a victim's position resolve to a worse efficiency group than it chose? `merge-price` attaches a price to an asset record by position in the fold, not by asset id, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `liquidate` with `min-collateral-expected`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
