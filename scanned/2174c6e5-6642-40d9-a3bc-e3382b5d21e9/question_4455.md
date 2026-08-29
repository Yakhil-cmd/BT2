# Q4455: vault-system-borrow via liquidate: prime shared state so the next caller in the block is eval

## Question
`vault-system-borrow` (mainnet/contracts/market/v0-4-market.clar:198) routes a borrow to one of six vaults by asset id. Can an unprivileged caller of `liquidate` (mainnet/contracts/market/v0-4-market.clar:1382), by choosing `borrower`, any third-party principal, use that to prime shared state so the next caller in the block is evaluated against it, violating the invariant that a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created and producing permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/market/v0-4-market.clar:198` -> `vault-system-borrow`
- Entrypoint: `liquidate` (`mainnet/contracts/market/v0-4-market.clar:1382`), unprivileged and publicly callable
- Attacker controls: `borrower`, any third-party principal
- Exploit idea: `vault-system-borrow` routes a borrow to one of six vaults by asset id. Reach it through `liquidate` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: a position can always be enumerated, priced, liquidated and withdrawn from whatever state others created
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `vault-system-borrow` touches, run `liquidate` with `borrower`, any third-party principal, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
