# Q2875: mask-to-list-iter via collateral-remove: push a third party's position past a fold bound so every e

## Question
`mask-to-list-iter` (mainnet/contracts/market/v0-4-market.clar:440) appends under `(unwrap-panic (as-max-len? ... u64))`, aborting if the position exceeds the bound. Can an unprivileged caller of `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), by choosing the `ft` trait principal, use that to push a third party's position past a fold bound so every evaluation of it aborts, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:440` -> `mask-to-list-iter`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `mask-to-list-iter` appends under `(unwrap-panic (as-max-len? ... u64))`, aborting if the position exceeds the bound. Reach it through `collateral-remove` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove` with the `ft` trait principal, then read `mask-to-list-iter` state before and after in the same block and assert the two sides of the invariant are equal.
