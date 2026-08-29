# Q0308: unpack-u16 via liquidate-redeem: reprice every other holder's collateral in the same transa

## Question
Does `liquidate-redeem` (mainnet/contracts/market/v0-4-market.clar:1604) let an unprivileged attacker who controls the borrower targeted reach `unpack-u16` (mainnet/contracts/vault/v0-vault-stx.clar:259) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it unpacks eight u16 curve fields from one packed word, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:259` -> `unpack-u16`
- Entrypoint: `liquidate-redeem` (`mainnet/contracts/market/v0-4-market.clar:1604`), unprivileged and publicly callable
- Attacker controls: the borrower targeted
- Exploit idea: `unpack-u16` unpacks eight u16 curve fields from one packed word. Reach it through `liquidate-redeem` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `liquidate-redeem` twice with the borrower targeted varied, and assert that the value `unpack-u16` returns is identical in both runs; a divergence confirms the finding.
