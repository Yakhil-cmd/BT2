# Q0038: vault-accrue via collateral-remove-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) while controlling `receiver` for the underlying leg, can an unprivileged attacker make `vault-accrue` (mainnet/contracts/market/v0-4-market.clar:189) write a stranger's ledger through an unsolicited on-behalf-of call? `vault-accrue` dispatches accrual to one of six vaults by asset id, so the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block would fail, yielding protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:189` -> `vault-accrue`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: `receiver` for the underlying leg
- Exploit idea: `vault-accrue` dispatches accrual to one of six vaults by asset id. Reach it through `collateral-remove-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `collateral-remove-redeem` twice with `receiver` for the underlying leg varied, and assert that the value `vault-accrue` returns is identical in both runs; a divergence confirms the finding.
