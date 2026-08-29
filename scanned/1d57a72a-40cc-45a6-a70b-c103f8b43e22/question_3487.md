# Q3487: check-confidence via liquidate: push a third party's position past a fold bound so every e

## Question
`check-confidence` (mainnet/contracts/market/v0-4-market.clar:305) compares the Pyth confidence interval against `max-confidence-ratio` in BPS, a gate that has no DIA equivalent. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing `collateral-receiver`, use that to push a third party's position past a fold bound so every evaluation of it aborts, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:305` -> `check-confidence`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `check-confidence` compares the Pyth confidence interval against `max-confidence-ratio` in BPS, a gate that has no DIA equivalent. Reach it through `liquidate` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with `collateral-receiver`, then read `check-confidence` state before and after in the same block and assert the two sides of the invariant are equal.
