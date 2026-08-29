# Q5328: find-collateral-amount via borrow: reprice every other holder's collateral in the same transa

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the future mask produced by the new debt bit reach `find-collateral-amount` (mainnet/contracts/market/v0-4-market.clar:609) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it returns u0 for an absent asset, making a missing row indistinguishable from a zero holding, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:609` -> `find-collateral-amount`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the future mask produced by the new debt bit
- Exploit idea: `find-collateral-amount` returns u0 for an absent asset, making a missing row indistinguishable from a zero holding. Reach it through `borrow` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the future mask produced by the new debt bit across its boundary values through `borrow` in simnet and assert `find-collateral-amount` never returns a value that breaks the invariant.
