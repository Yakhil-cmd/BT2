# Q1728: resolve-dia via collateral-remove-redeem: write a stranger's ledger through an unsolicited on-behalf

## Question
Does `collateral-remove-redeem` (mainnet/contracts/market/v0-4-market.clar:1211) let an unprivileged attacker who controls the zToken/underlying id mapping reached (the u100 sentinel branch) reach `resolve-dia` (mainnet/contracts/market/v0-4-market.clar:326) in a state where it write a stranger's ledger through an unsolicited on-behalf-of call? Given that it derives a (string-ascii 32) key from a (buff 32) ident, the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:326` -> `resolve-dia`
- Entrypoint: `collateral-remove-redeem` (`mainnet/contracts/market/v0-4-market.clar:1211`), unprivileged and publicly callable
- Attacker controls: the zToken/underlying id mapping reached (the u100 sentinel branch)
- Exploit idea: `resolve-dia` derives a (string-ascii 32) key from a (buff 32) ident. Reach it through `collateral-remove-redeem` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the zToken/underlying id mapping reached (the u100 sentinel branch) across its boundary values through `collateral-remove-redeem` in simnet and assert `resolve-dia` never returns a value that breaks the invariant.
