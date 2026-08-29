# Q3493: calculate-asset-notional-value via collateral-add: prime shared state so the next caller in the block is eval

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling the position's existing collateral and debt composition, drive `calculate-asset-notional-value` (mainnet/contracts/market/v0-4-market.clar:544) — which normalizes collateral with round-down and debt with round-up, and calls `accrue-and-cache` with `unwrap-panic` inside the fold — to prime shared state so the next caller in the block is evaluated against it, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:544` -> `calculate-asset-notional-value`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: the position's existing collateral and debt composition
- Exploit idea: `calculate-asset-notional-value` normalizes collateral with round-down and debt with round-up, and calls `accrue-and-cache` with `unwrap-panic` inside the fold. Reach it through `collateral-add` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-add` with the position's existing collateral and debt composition, then read `calculate-asset-notional-value` state before and after in the same block and assert the two sides of the invariant are equal.
