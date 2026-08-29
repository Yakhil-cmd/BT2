# Q5200: socialize-debt via liquidate: prime shared state so the next caller in the block is eval

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `min-collateral-expected` reach `socialize-debt` (mainnet/contracts/vault/v0-vault-stx.clar:944) in a state where it prime shared state so the next caller in the block is evaluated against it? Given that it writes down `lindex` by one ratio while reducing `assets` by a completely different `principal-reduction`, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is theft of unclaimed yield.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:944` -> `socialize-debt`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `socialize-debt` writes down `lindex` by one ratio while reducing `assets` by a completely different `principal-reduction`. Reach it through `liquidate` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: Set up the position in simnet, call `liquidate` with `min-collateral-expected`, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
