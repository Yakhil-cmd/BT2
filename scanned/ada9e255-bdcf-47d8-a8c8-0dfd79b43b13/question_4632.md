# Q4632: accrue-user-collateral via liquidate-redeem: reprice every other holder's collateral in the same transa

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the borrower targeted reach `accrue-user-collateral` (mainnet/contracts/market/v0-4-market.clar:270) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it accrues only rows that `is-ztoken` recognises, skipping everything else, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:270` -> `accrue-user-collateral`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the borrower targeted
- Exploit idea: `accrue-user-collateral` accrues only rows that `is-ztoken` recognises, skipping everything else. Reach it through `liquidate-redeem` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz the borrower targeted across its boundary values through `liquidate-redeem` in simnet and assert `accrue-user-collateral` never returns a value that breaks the invariant.
