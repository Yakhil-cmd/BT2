# Q1254: calc-liq-debt-repay via liquidate: prime shared state so the next caller in the block is eval

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `borrower`, any third-party principal, can an unprivileged attacker make `calc-liq-debt-repay` (mainnet/contracts/market/v0-4-market.clar:723) prime shared state so the next caller in the block is evaluated against it? `calc-liq-debt-repay` takes the liquidation factor times the debt with `mul-bps-down`, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding permanent freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:723` -> `calc-liq-debt-repay`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `borrower`, any third-party principal
- Exploit idea: `calc-liq-debt-repay` takes the liquidation factor times the debt with `mul-bps-down`. Reach it through `liquidate` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Fuzz `borrower`, any third-party principal across its boundary values through `liquidate` in simnet and assert `calc-liq-debt-repay` never returns a value that breaks the invariant.
