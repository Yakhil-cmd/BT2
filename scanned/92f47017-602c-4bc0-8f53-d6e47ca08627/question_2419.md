# Q2419: total-assets-preview via collateral-remove-redeem: prime shared state so the next caller in the block is eval

## Question
`total-assets-preview` (mainnet/contracts/vault/v0-vault-stx.clar:341) re-derives a FORWARD index inside calls that have already accrued. Can an unprivileged caller of `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211), by choosing `amount` used for BOTH the collateral removal and the share redemption, use that to prime shared state so the next caller in the block is evaluated against it, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:341` -> `total-assets-preview`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `amount` used for BOTH the collateral removal and the share redemption
- Exploit idea: `total-assets-preview` re-derives a FORWARD index inside calls that have already accrued. Reach it through `collateral-remove-redeem` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `collateral-remove-redeem` with `amount` used for BOTH the collateral removal and the share redemption, then read `total-assets-preview` state before and after in the same block and assert the two sides of the invariant are equal.
