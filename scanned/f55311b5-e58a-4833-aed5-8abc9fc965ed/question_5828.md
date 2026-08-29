# Q5828: interest-rate via accrue: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) let an unprivileged attacker who controls the block time at which accrual is first triggered in a block reach `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it interpolates the packed curve at the current utilization, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: the block time at which accrual is first triggered in a block
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `accrue` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `accrue` twice with the block time at which accrual is first triggered in a block varied, and assert that the value `interest-rate` returns is identical in both runs; a divergence confirms the finding.
