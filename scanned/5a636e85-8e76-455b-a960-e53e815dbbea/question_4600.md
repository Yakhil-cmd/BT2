# Q4600: accrue-user-debts via call-ststx-ratio: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `call-ststx-ratio` (mainnet/contracts/market/v0-4-market.clar:1015) let an unprivileged attacker who controls whether the ratio is fetched before or after other state changes in the block reach `accrue-user-debts` (mainnet/contracts/market/v0-4-market.clar:259) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it folds accrual over the position's debt list only, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is direct theft of user funds at rest or in motion.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:259` -> `accrue-user-debts`
- Entrypoint: `call-ststx-ratio` (`mainnet/contracts/market/v0-4-market.clar:1015`), unprivileged and publicly callable
- Attacker controls: whether the ratio is fetched before or after other state changes in the block
- Exploit idea: `accrue-user-debts` folds accrual over the position's debt list only. Reach it through `call-ststx-ratio` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: Set up the position in simnet, call `call-ststx-ratio` with whether the ratio is fetched before or after other state changes in the block, and assert on the printed event plus the post-state that collateral, debt and share totals still reconcile.
