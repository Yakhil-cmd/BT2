# Q1205: remove-user-scaled-debt via borrow: prime shared state so the next caller in the block is eval

## Question
Can an unprivileged attacker entering through `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), controlling the order of accrual versus price resolution inside the let, drive `remove-user-scaled-debt` (mainnet/contracts/market/v0-market-vault.clar:244) — which deletes the row only on an exact zero, otherwise leaving a residue that keeps the mask bit set — to prime shared state so the next caller in the block is evaluated against it, breaking the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment, and cause protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:244` -> `remove-user-scaled-debt`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the order of accrual versus price resolution inside the let
- Exploit idea: `remove-user-scaled-debt` deletes the row only on an exact zero, otherwise leaving a residue that keeps the mask bit set. Reach it through `borrow` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `borrow` call, then the attacker-shaped one with the order of accrual versus price resolution inside the let, and assert the attacker's net token balance change is zero or negative.
