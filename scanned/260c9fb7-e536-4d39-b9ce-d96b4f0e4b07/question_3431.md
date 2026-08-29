# Q3431: find-superset via liquidate: push a third party's position past a fold bound so every e

## Question
`find-superset` (mainnet/contracts/registry/v0-egroup.clar:262) returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing `debt-amount`, use that to push a third party's position past a fold bound so every evaluation of it aborts, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing protocol insolvency?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:262` -> `find-superset`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `find-superset` returns the FIRST mask that is a superset, walking buckets in population order rather than finding the tightest. Reach it through `liquidate` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `liquidate` call, then the attacker-shaped one with `debt-amount`, and assert the attacker's net token balance change is zero or negative.
