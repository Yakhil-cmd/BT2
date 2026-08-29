# Q2492: socialize-debt-asset via liquidate: make a victim's position resolve to a worse efficiency gro

## Question
Does `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382) let an unprivileged attacker who controls `collateral-receiver` reach `socialize-debt-asset` (mainnet/contracts/market/v0-4-market.clar:879) in a state where it make a victim's position resolve to a worse efficiency group than it chose? Given that it calls the vault write-down, then overwrites `index-cache` for the current timestamp mid-fold, and carries a `success` flag that short-circuits, the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends breaks and the result is protocol insolvency.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:879` -> `socialize-debt-asset`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `collateral-receiver`
- Exploit idea: `socialize-debt-asset` calls the vault write-down, then overwrites `index-cache` for the current timestamp mid-fold, and carries a `success` flag that short-circuits. Reach it through `liquidate` and make a victim's position resolve to a worse efficiency group than it chose.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Write a Clarinet simnet test calling `liquidate` twice with `collateral-receiver` varied, and assert that the value `socialize-debt-asset` returns is identical in both runs; a divergence confirms the finding.
