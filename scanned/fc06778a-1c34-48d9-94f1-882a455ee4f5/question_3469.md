# Q3469: merge-price via collateral-remove-redeem: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211), controlling `min-underlying`, drive `merge-price` (mainnet/contracts/market/v0-4-market.clar:506) — which attaches a price to an asset record by position in the fold, not by asset id — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `min-underlying`
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `collateral-remove-redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove-redeem` with `min-underlying`, then read `merge-price` state before and after in the same block and assert the two sides of the invariant are equal.
