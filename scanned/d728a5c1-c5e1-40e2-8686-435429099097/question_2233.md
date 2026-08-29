# Q2233: calc-liq-debt-repay via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Can an unprivileged attacker entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), controlling `min-collateral-expected`, drive `calc-liq-debt-repay` (mainnet/contracts/market/v0-4-market.clar:723) — which takes the liquidation factor times the debt with `mul-bps-down` — to make a victim's position resolve to a worse efficiency group than it chose, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:723` -> `calc-liq-debt-repay`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `calc-liq-debt-repay` takes the liquidation factor times the debt with `mul-bps-down`. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with `min-collateral-expected`, then read `calc-liq-debt-repay` state before and after in the same block and assert the two sides of the invariant are equal.
