# Q3037: write-feed via collateral-remove: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), controlling whether the position has any enabled debt row (the has-debt branch), drive `write-feed` (mainnet/contracts/market/v0-4-market.clar:129) — which applies one Pyth price-feed update and folds its status — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:129` -> `write-feed`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: whether the position has any enabled debt row (the has-debt branch)
- Exploit idea: `write-feed` applies one Pyth price-feed update and folds its status. Reach it through `collateral-remove` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove` with whether the position has any enabled debt row (the has-debt branch), then read `write-feed` state before and after in the same block and assert the two sides of the invariant are equal.
