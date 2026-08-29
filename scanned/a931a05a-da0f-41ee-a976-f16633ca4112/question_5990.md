# Q5990: vault-accrue via accrue: make a victim's position resolve to a worse efficiency gro

## Question
Entering through `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835) while controlling the utilization the rate is interpolated at, can an unprivileged attacker make `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) make a victim's position resolve to a worse efficiency group than it chose? `vault-accrue` dispatches accrual to one of six vaults by asset id, so the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block would fail, yielding protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: the utilization the rate is interpolated at
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `accrue` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `accrue` twice with the utilization the rate is interpolated at varied, and assert that the value `vault-accrue` returns is identical in both runs; a divergence confirms the finding.
