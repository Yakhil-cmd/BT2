# Q5427: merge-price via collateral-remove-redeem: make a victim's position resolve to a worse efficiency gro

## Question
`merge-price` (mainnet/contracts/market/v0-4-market.clar:506) attaches a price to an asset record by position in the fold, not by asset id. Can an unprivileged caller of `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211), by choosing `min-underlying`, use that to make a victim's position resolve to a worse efficiency group than it chose, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `min-underlying`
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `collateral-remove-redeem` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `merge-price` touches, run `collateral-remove-redeem` with `min-underlying`, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
