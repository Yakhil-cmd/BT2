# Q5235: system-repay via liquidate-multi: prime shared state so the next caller in the block is eval

## Question
`system-repay` (mainnet/contracts/vault/v0-vault-stx.clar:902) splits one payment with three different formulas for `principal-reduction`, `principal-repaid` and `interest-paid`. Can an unprivileged caller of `liquidate-multi` (mainnet/contracts/market/v0-4-market.clar:1593), by choosing the trait principals supplied per entry, use that to prime shared state so the next caller in the block is evaluated against it, violating the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends and producing permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:902` -> `system-repay`
- Entrypoint: `liquidate-multi` (`mainnet/contracts/market/v0-4-market.clar:1593`), unprivileged and publicly callable
- Attacker controls: the trait principals supplied per entry
- Exploit idea: `system-repay` splits one payment with three different formulas for `principal-reduction`, `principal-repaid` and `interest-paid`. Reach it through `liquidate-multi` and prime shared state so the next caller in the block is evaluated against it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `system-repay` touches, run `liquidate-multi` with the trait principals supplied per entry, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
