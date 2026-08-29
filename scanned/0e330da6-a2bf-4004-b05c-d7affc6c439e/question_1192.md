# Q1192: find-collateral-amount via liquidate-redeem: push a third party's position past a fold bound so every e

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the seized zToken amount that is immediately redeemed reach `find-collateral-amount` (mainnet/contracts/market/v0-4-market.clar:609) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it returns u0 for an absent asset, making a missing row indistinguishable from a zero holding, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is direct theft of another user's collateral.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:609` -> `find-collateral-amount`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the seized zToken amount that is immediately redeemed
- Exploit idea: `find-collateral-amount` returns u0 for an absent asset, making a missing row indistinguishable from a zero holding. Reach it through `liquidate-redeem` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: Set up the position in simnet, call `liquidate-redeem` with the seized zToken amount that is immediately redeemed, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
