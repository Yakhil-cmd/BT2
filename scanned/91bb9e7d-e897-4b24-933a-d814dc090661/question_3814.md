# Q3814: find via borrow: route a victim's mandatory payout through a principal that

## Question
Entering through `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) while controlling `amount`, can an unprivileged attacker make `find` (mainnet/contracts/registry/v0-assets.clar:135) route a victim's mandatory payout through a principal that always rejects delivery? `find` resolves an asset record from a principal through the `reverse` map, so the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/registry/v0-assets.clar:135` -> `find`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `find` resolves an asset record from a principal through the `reverse` map. Reach it through `borrow` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `borrow` with `amount`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
