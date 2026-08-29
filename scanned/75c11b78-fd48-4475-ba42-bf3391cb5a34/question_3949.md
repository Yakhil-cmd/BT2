# Q3949: linear-interpolate via deposit: write a stranger's ledger through an unsolicited on-behalf

## Question
Can an unprivileged attacker entering through `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763), controlling `recipient`, including a contract principal, drive `linear-interpolate` (mainnet/contracts/vault/v0-vault-stx.clar:221) — which interpolates between two points, dividing by `(- x2 x1)` — to write a stranger's ledger through an unsolicited on-behalf-of call, breaking the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created, and cause theft of unclaimed yield?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:221` -> `linear-interpolate`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `recipient`, including a contract principal
- Exploit idea: `linear-interpolate` interpolates between two points, dividing by `(- x2 x1)`. Reach it through `deposit` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - theft of unclaimed yield
- Fast validation: In `local-testing/tests` on a local fork, drive `deposit` with `recipient`, including a contract principal, then read `linear-interpolate` state before and after in the same block and assert the two sides of the invariant are equal.
