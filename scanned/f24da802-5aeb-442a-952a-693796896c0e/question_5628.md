# Q5628: collateral-remove via transfer: push a third party's position past a fold bound so every e

## Question
Does `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) let an unprivileged attacker who controls `amount` reach `collateral-remove` (mainnet/contracts/market/v0-market-vault.clar:406) in a state where it push a third party's position past a fold bound so every evaluation of it aborts? Given that it decrements the map and writes the entry before `send-tokens` executes, the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:406` -> `collateral-remove`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `collateral-remove` decrements the map and writes the entry before `send-tokens` executes. Reach it through `transfer` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `amount` across its boundary values through `transfer` in simnet and assert `collateral-remove` never returns a value that breaks the invariant.
