# Q4903: convert-to-scaled-debt via liquidate-redeem: seize from a position that is solvent under the mask its o

## Question
`convert-to-scaled-debt` (mainnet/contracts/market/v0-4-market.clar:648) scales a token amount by the cached borrow index, rounding up on the borrow path. Can an unprivileged caller of `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), by choosing the borrower targeted, use that to seize from a position that is solvent under the mask its own operations were validated against, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:648` -> `convert-to-scaled-debt`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the borrower targeted
- Exploit idea: `convert-to-scaled-debt` scales a token amount by the cached borrow index, rounding up on the borrow path. Reach it through `liquidate-redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate-redeem` with the borrower targeted, then read `convert-to-scaled-debt` state before and after in the same block and assert the two sides of the invariant are equal.
