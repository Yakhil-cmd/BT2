# Q4987: merge-price via liquidate-multi: seize from a position that is solvent under the mask its o

## Question
`merge-price` (mainnet/contracts/market/v0-4-market.clar:506) attaches a price to an asset record by position in the fold, not by asset id. Can an unprivileged caller of `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593), by choosing the trait principals supplied per entry, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `liquidate-multi` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate-multi` with the trait principals supplied per entry, then read `merge-price` state before and after in the same block and assert the two sides of the invariant are equal.
