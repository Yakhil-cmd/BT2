# Q4040: remove-user-collateral via borrow: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls the order of accrual versus price resolution inside the let reach `remove-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:205) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it asserts sufficiency then `map-delete`s only on an exact zero, the invariant that the only writes to a third party's position are a correct liquidation and a debt-reducing repayment breaks and the result is permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:205` -> `remove-user-collateral`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the order of accrual versus price resolution inside the let
- Exploit idea: `remove-user-collateral` asserts sufficiency then `map-delete`s only on an exact zero. Reach it through `borrow` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: the only writes to a third party's position are a correct liquidation and a debt-reducing repayment
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with the order of accrual versus price resolution inside the let varied, and assert that the value `remove-user-collateral` returns is identical in both runs; a divergence confirms the finding.
