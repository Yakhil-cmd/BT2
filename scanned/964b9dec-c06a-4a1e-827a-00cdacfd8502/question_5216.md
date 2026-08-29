# Q5216: uint-to-list-u64 via borrow: reprice every other holder's collateral in the same transa

## Question
Does `borrow` (mainnet/contracts/market/v0-4-market.clar:1238) let an unprivileged attacker who controls `amount` reach `uint-to-list-u64` (mainnet/contracts/registry/v0-assets.clar:80) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it expands a bitmap into a 64-element list, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/registry/v0-assets.clar:80` -> `uint-to-list-u64`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `uint-to-list-u64` expands a bitmap into a 64-element list. Reach it through `borrow` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `borrow` twice with `amount` varied, and assert that the value `uint-to-list-u64` returns is identical in both runs; a divergence confirms the finding.
