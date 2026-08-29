# Q4551: get-notional-evaluation via collateral-remove: write a stranger's ledger through an unsolicited on-behalf

## Question
`get-notional-evaluation` (mainnet/contracts/market/v0-4-market.clar:514) folds over the ENABLED asset list, so a position row whose asset is absent from that list contributes nothing to either total. Can an unprivileged caller of `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107), by choosing `amount` relative to the current collateral row (the removing-all branch), use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:514` -> `get-notional-evaluation`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: `amount` relative to the current collateral row (the removing-all branch)
- Exploit idea: `get-notional-evaluation` folds over the ENABLED asset list, so a position row whose asset is absent from that list contributes nothing to either total. Reach it through `collateral-remove` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `get-notional-evaluation` touches, run `collateral-remove` with `amount` relative to the current collateral row (the removing-all branch), recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
