# Q5636: resolve-or-create via repay: reprice every other holder's collateral in the same transa

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls `amount`, including far above the real debt (the capping path) reach `resolve-or-create` (mainnet/contracts/market/v0-market-vault.clar:143) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it allocates a user id through `increment` for whatever principal the market names, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:143` -> `resolve-or-create`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `amount`, including far above the real debt (the capping path)
- Exploit idea: `resolve-or-create` allocates a user id through `increment` for whatever principal the market names. Reach it through `repay` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `repay` twice with `amount`, including far above the real debt (the capping path) varied, and assert that the value `resolve-or-create` returns is identical in both runs; a divergence confirms the finding.
