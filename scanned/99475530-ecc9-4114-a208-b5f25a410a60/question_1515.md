# Q1515: subset via liquidate-multi: reprice every other holder's collateral in the same transa

## Question
`subset` (mainnet/contracts/market/v0-market-vault.clar:100) tests bitmask containment. Can an unprivileged caller of `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593), by choosing the trait principals supplied per entry, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:100` -> `subset`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `subset` tests bitmask containment. Reach it through `liquidate-multi` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `subset` touches, run `liquidate-multi` with the trait principals supplied per entry, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
