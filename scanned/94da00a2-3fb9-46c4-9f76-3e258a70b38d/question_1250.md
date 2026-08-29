# Q1250: resolve-dia via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Entering through `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) while controlling `min-collateral-expected`, can an unprivileged attacker make `resolve-dia` (mainnet/contracts/market/v0-4-market.clar:326) make a victim's position resolve to a worse efficiency group than it chose? `resolve-dia` derives a (string-ascii 32) key from a (buff 32) ident, so the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created would fail, yielding permanent freezing of unclaimed yield.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:326` -> `resolve-dia`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `min-collateral-expected`
- Exploit idea: `resolve-dia` derives a (string-ascii 32) key from a (buff 32) ident. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - permanent freezing of unclaimed yield
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `min-collateral-expected` varied, and assert that the value `resolve-dia` returns is identical in both runs; a divergence confirms the finding.
