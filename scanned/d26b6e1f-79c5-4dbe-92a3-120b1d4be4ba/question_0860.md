# Q0860: call-liquidate via liquidate: push a third party's position past a fold bound so every e

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `debt-amount` reach `call-liquidate` (mainnet/contracts/market/v0-4-market.clar:907) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it invokes `liquidate` with `none` for price-feeds, so a whole batch shares one snapshot, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is protocol insolvency through uncollateralised debt.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:907` -> `call-liquidate`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `debt-amount`
- Exploit idea: `call-liquidate` invokes `liquidate` with `none` for price-feeds, so a whole batch shares one snapshot. Reach it through `liquidate` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `debt-amount` varied, and assert that the value `call-liquidate` returns is identical in both runs; a divergence confirms the finding.
