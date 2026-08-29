# Q5988: interpolate-rate via liquidate: push a third party's position past a fold bound so every e

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls the `price-feeds` buffers and their ordering reach `interpolate-rate` (mainnet/contracts/vault/v0-vault-stx.clar:196) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it interpolates between packed u16 curve points, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:196` -> `interpolate-rate`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: the `price-feeds` buffers and their ordering
- Exploit idea: `interpolate-rate` interpolates between packed u16 curve points. Reach it through `liquidate` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz the `price-feeds` buffers and their ordering across its boundary values through `liquidate` in simnet and assert `interpolate-rate` never returns a value that breaks the invariant.
