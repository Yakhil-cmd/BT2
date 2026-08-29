# Q2299: zip via supply-collateral-add: route a victim's mandatory payout through a principal that

## Question
`zip` (mainnet/contracts/vault/v0-vault-stx.clar:226) pairs the utilization and rate point lists element by element. Can an unprivileged caller of `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), by choosing `amount`, use that to route a victim's mandatory payout through a principal that always rejects delivery, violating the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more and producing direct theft of another user's collateral?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:226` -> `zip`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `zip` pairs the utilization and rate point lists element by element. Reach it through `supply-collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - direct theft of another user's collateral
- Fast validation: In `local-testing/tests` on a local fork, drive `supply-collateral-add` with `amount`, then read `zip` state before and after in the same block and assert the two sides of the invariant are equal.
