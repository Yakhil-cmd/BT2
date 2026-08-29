# Q3330: resolve via liquidate: write a stranger's ledger through an unsolicited on-behalf

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `min-collateral-expected`, can an unprivileged attacker make `resolve` (mainnet/contracts/registry/v0-egroup.clar:360) write a stranger's ledger through an unsolicited on-behalf-of call? `resolve` selects the efficiency group for a position mask, so the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements would fail, yielding temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:360` -> `resolve`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `resolve` selects the efficiency group for a position mask. Reach it through `liquidate` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz `min-collateral-expected` across its boundary values through `liquidate` in simnet and assert `resolve` never returns a value that breaks the invariant.
