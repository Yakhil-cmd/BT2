# Q4306: merge-price via liquidate-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) while controlling the redemption receiver, can an unprivileged attacker make `merge-price` (mainnet/contracts/market/v0-4-market.clar:506) write a stranger's ledger through an unsolicited on-behalf-of call? `merge-price` attaches a price to an asset record by position in the fold, not by asset id, so the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment would fail, yielding direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:506` -> `merge-price`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the redemption receiver
- Exploit idea: `merge-price` attaches a price to an asset record by position in the fold, not by asset id. Reach it through `liquidate-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `liquidate-redeem` with the redemption receiver, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
