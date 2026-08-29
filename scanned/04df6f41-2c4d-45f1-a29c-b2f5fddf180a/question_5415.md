# Q5415: total-debt via supply-collateral-add: write a stranger's ledger through an unsolicited on-behalf

## Question
`total-debt` (mainnet/contracts/vault/v0-vault-stx.clar:328) computes cumulative debt from `principal-scaled` and `index`. Can an unprivileged caller of `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), by choosing the position state the final collateral-add is validated against, use that to write a stranger's ledger through an unsolicited on-behalf-of call, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:328` -> `total-debt`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: the position state the final collateral-add is validated against
- Exploit idea: `total-debt` computes cumulative debt from `principal-scaled` and `index`. Reach it through `supply-collateral-add` and write a stranger's ledger through an unsolicited on-behalf-of call.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `total-debt` touches, run `supply-collateral-add` with the position state the final collateral-add is validated against, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
