# Q0686: is-healthy-with-mask via supply-collateral-add: reprice every other holder's collateral in the same transa

## Question
Entering through `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175) while controlling `amount`, can an unprivileged attacker make `is-healthy-with-mask` (mainnet/contracts/market/v0-4-market.clar:663) reprice every other holder's collateral in the same transaction that profits from it? `is-healthy-with-mask` resolves an egroup for a caller-influenced mask and applies its LTV-BORROW, so the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block would fail, yielding protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:663` -> `is-healthy-with-mask`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `is-healthy-with-mask` resolves an egroup for a caller-influenced mask and applies its LTV-BORROW. Reach it through `supply-collateral-add` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `supply-collateral-add` twice with `amount` varied, and assert that the value `is-healthy-with-mask` returns is identical in both runs; a divergence confirms the finding.
