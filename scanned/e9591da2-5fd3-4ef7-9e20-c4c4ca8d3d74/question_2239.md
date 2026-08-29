# Q2239: principal-ratio-reduction via supply-collateral-add: reprice every other holder's collateral in the same transa

## Question
`principal-ratio-reduction` (mainnet/contracts/vault/v0-vault-stx.clar:406) derives a principal reduction from an amount, the scaled principal and the previewed debt. Can an unprivileged caller of `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), by choosing `amount`, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:406` -> `principal-ratio-reduction`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `principal-ratio-reduction` derives a principal reduction from an amount, the scaled principal and the previewed debt. Reach it through `supply-collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `supply-collateral-add` with `amount`, then read `principal-ratio-reduction` state before and after in the same block and assert the two sides of the invariant are equal.
