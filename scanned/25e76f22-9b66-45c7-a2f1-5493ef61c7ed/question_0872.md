# Q0872: interest-rate via repay: route a victim's mandatory payout through a principal that

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls whether the repaid asset is in the accrued debt list reach `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it interpolates the packed curve at the current utilization, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: whether the repaid asset is in the accrued debt list
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `repay` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `repay` twice with whether the repaid asset is in the accrued debt list varied, and assert that the value `interest-rate` returns is identical in both runs; a divergence confirms the finding.
