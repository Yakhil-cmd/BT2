# Q0350: vault-accrue via liquidate: reprice every other holder's collateral in the same transa

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `debt-amount`, can an unprivileged attacker make `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) reprice every other holder's collateral in the same transaction that profits from it? `vault-accrue` dispatches accrual to one of six vaults by asset id, so the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block would fail, yielding permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `liquidate` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `debt-amount` varied, and assert that the value `vault-accrue` returns is identical in both runs; a divergence confirms the finding.
