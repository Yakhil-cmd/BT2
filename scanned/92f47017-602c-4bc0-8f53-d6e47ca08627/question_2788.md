# Q2788: is-liquidation-paused via liquidate-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the redemption receiver reach `is-liquidation-paused` (mainnet/contracts/market/v0-4-market.clar:691) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it returns true if the manual pause, the GLOBAL grace entry, OR the per-asset grace entry is live, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is theft of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:691` -> `is-liquidation-paused`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the redemption receiver
- Exploit idea: `is-liquidation-paused` returns true if the manual pause, the GLOBAL grace entry, OR the per-asset grace entry is live. Reach it through `liquidate-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: Set up the position in simnet, call `liquidate-redeem` with the redemption receiver, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
