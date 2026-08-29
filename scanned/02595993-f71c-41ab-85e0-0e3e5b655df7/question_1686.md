# Q1686: lookup via liquidate: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `borrower`, any third-party principal, can an unprivileged attacker make `lookup` (mainnet/contracts/registry/v0-assets.clar:139) write a stranger's ledger through an unsolicited on-behalf-of call? `lookup` returns the registry record, including the `decimals` captured once at registration, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/registry/v0-assets.clar:139` -> `lookup`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `borrower`, any third-party principal
- Exploit idea: `lookup` returns the registry record, including the `decimals` captured once at registration. Reach it through `liquidate` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `borrower`, any third-party principal across its boundary values through `liquidate` in simnet and assert `lookup` never returns a value that breaks the invariant.
