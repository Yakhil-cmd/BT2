# Q3569: iter-find-superset via collateral-add: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), controlling `amount`, drive `iter-find-superset` (mainnet/contracts/registry/v0-egroup.clar:267) — which short-circuits on the first superset match — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:267` -> `iter-find-superset`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `iter-find-superset` short-circuits on the first superset match. Reach it through `collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `collateral-add` call, then the attacker-shaped one with `amount`, and assert the attacker's net token balance change is zero or negative.
