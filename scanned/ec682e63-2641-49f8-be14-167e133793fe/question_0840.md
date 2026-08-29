# Q0840: interest-rate via liquidate-multi: reprice every other holder's collateral in the same transa

## Question
Does `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593) let an unprivileged attacker who controls the trait principals supplied per entry reach `interest-rate` (mainnet/contracts/vault/v0-vault-stx.clar:371) in a state where it reprice every other holder's collateral in the same transaction that profits from it? Given that it interpolates the packed curve at the current utilization, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:371` -> `interest-rate`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `interest-rate` interpolates the packed curve at the current utilization. Reach it through `liquidate-multi` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz the trait principals supplied per entry across its boundary values through `liquidate-multi` in simnet and assert `interest-rate` never returns a value that breaks the invariant.
