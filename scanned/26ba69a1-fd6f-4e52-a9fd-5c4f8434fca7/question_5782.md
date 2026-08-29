# Q5782: relevant via repay: push a third party's position past a fold bound so every e

## Question
Entering through `repay` (mainnet/contracts/market/v0-4-market.clar:1316) while controlling the `ft` trait principal, can an unprivileged attacker make `relevant` (mainnet/contracts/market/v0-market-vault.clar:175) push a third party's position past a fold bound so every evaluation of it aborts? `relevant` drops any position row whose bit is not present in the enabled mask, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:175` -> `relevant`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `relevant` drops any position row whose bit is not present in the enabled mask. Reach it through `repay` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `repay` with the `ft` trait principal, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
