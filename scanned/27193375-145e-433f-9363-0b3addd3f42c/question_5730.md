# Q5730: add-user-collateral via transfer: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `transfer` (mainnet/contracts/vault/v0-vault-stx.clar:752) while controlling `amount`, can an unprivileged attacker make `add-user-collateral` (mainnet/contracts/market/v0-market-vault.clar:198) write a stranger's ledger through an unsolicited on-behalf-of call? `add-user-collateral` adds to the collateral row with a graceful u0 default, so the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more would fail, yielding permanent freezing of a position that can never be closed.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:198` -> `add-user-collateral`
- Entrypoint: `transfer` (`mainnet/contracts/vault/v0-vault-stx.clar:752`), unprivileged and publicly callable
- Attacker controls: `amount`
- Exploit idea: `add-user-collateral` adds to the collateral row with a graceful u0 default. Reach it through `transfer` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Fuzz `amount` across its boundary values through `transfer` in simnet and assert `add-user-collateral` never returns a value that breaks the invariant.
