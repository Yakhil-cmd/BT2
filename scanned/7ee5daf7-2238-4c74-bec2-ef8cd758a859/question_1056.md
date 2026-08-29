# Q1056: linear-interpolate via repay: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `repay` (mainnet/contracts/market/v0-4-market.clar:1316) let an unprivileged attacker who controls `amount`, including far above the real debt (the capping path) reach `linear-interpolate` (mainnet/contracts/vault/v0-vault-stx.clar:221) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it interpolates between two points, dividing by `(- x2 x1)`, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:221` -> `linear-interpolate`
- Entrypoint: `repay` (`mainnet/contracts/market/v0-4-market.clar:1316`), unprivileged and publicly callable
- Attacker controls: `amount`, including far above the real debt (the capping path)
- Exploit idea: `linear-interpolate` interpolates between two points, dividing by `(- x2 x1)`. Reach it through `repay` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `amount`, including far above the real debt (the capping path) across its boundary values through `repay` in simnet and assert `linear-interpolate` never returns a value that breaks the invariant.
