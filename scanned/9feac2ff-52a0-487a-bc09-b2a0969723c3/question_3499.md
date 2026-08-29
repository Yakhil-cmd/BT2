# Q3499: get-notional-evaluation via liquidate: route a victim's mandatory payout through a principal that

## Question
`get-notional-evaluation` (mainnet/contracts/market/v0-4-market.clar:514) folds over the ENABLED asset list, so a position row whose asset is absent from that list contributes nothing to either total. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing `collateral-receiver`, use that to route a victim's mandatory payout through a principal that always rejects delivery, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:514` -> `get-notional-evaluation`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `get-notional-evaluation` folds over the ENABLED asset list, so a position row whose asset is absent from that list contributes nothing to either total. Reach it through `liquidate` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate` with `collateral-receiver`, then read `get-notional-evaluation` state before and after in the same block and assert the two sides of the invariant are equal.
