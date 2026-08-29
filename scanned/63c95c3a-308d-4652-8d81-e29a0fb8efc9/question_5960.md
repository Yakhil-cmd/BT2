# Q5960: next-index via deposit: push a third party's position past a fold bound so every e

## Question
Does `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763) let an unprivileged attacker who controls `amount` reach `next-index` (mainnet/contracts/vault/v0-vault-stx.clar:379) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it returns the stale `index` unchanged when the accrue pause state is set, instead of reverting, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:379` -> `next-index`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `next-index` returns the stale `index` unchanged when the accrue pause state is set, instead of reverting. Reach it through `deposit` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `deposit` twice with `amount` varied, and assert that the value `next-index` returns is identical in both runs; a divergence confirms the finding.
