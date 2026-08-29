# Q4153: calc-final-liquidation-amounts via liquidate-redeem: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604), controlling the seized zToken amount that is immediately redeemed, drive `calc-final-liquidation-amounts` (mainnet/contracts/market/v0-4-market.clar:834) — which recomputes debt proportionally when collateral was capped, a SECOND re-derivation after `process-debt-asset` already capped once — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created, and cause direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:834` -> `calc-final-liquidation-amounts`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the seized zToken amount that is immediately redeemed
- Exploit idea: `calc-final-liquidation-amounts` recomputes debt proportionally when collateral was capped, a SECOND re-derivation after `process-debt-asset` already capped once. Reach it through `liquidate-redeem` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `liquidate-redeem` with the seized zToken amount that is immediately redeemed, then read `calc-final-liquidation-amounts` state before and after in the same block and assert the two sides of the invariant are equal.
