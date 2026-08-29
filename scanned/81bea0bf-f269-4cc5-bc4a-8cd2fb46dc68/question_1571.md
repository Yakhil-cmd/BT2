# Q1571: create via collateral-add: reprice every other holder's collateral in the same transa

## Question
`create` (mainnet/contracts/market/v0-market-vault.clar:150) binds a principal to a fresh numeric id. Can an unprivileged caller of `collateral-add` (mainnet/contracts/market/v0-4-market.clar:1020), by choosing call ordering within the block, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment and producing protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:150` -> `create`
- Entrypoint: `collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1020`), unprivileged and publicly callable
- Attacker controls: call ordering within the block
- Exploit idea: `create` binds a principal to a fresh numeric id. Reach it through `collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `collateral-add` call, then the attacker-shaped one with call ordering within the block, and assert the attacker's net token balance change is zero or negative.
