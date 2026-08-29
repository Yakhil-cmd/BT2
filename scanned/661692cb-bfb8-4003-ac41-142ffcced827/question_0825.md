# Q0825: system-repay via borrow: push a third party's position past a fold bound so every e

## Question
Can an unprivileged attacker entering through `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), controlling the `ft` trait principal, drive `system-repay` (mainnet/contracts/vault/v0-vault-stx.clar:902) — which splits one payment with three different formulas for `principal-reduction`, `principal-repaid` and `interest-paid` — to push a third party's position past a fold bound so every evaluation of it aborts, breaking the invariant that no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements, and cause permanent freezing of a position that can never be closed?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:902` -> `system-repay`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: the `ft` trait principal
- Exploit idea: `system-repay` splits one payment with three different formulas for `principal-reduction`, `principal-repaid` and `interest-paid`. Reach it through `borrow` and push a third party's position past a fold bound so every evaluation of it aborts.
- Invariant to test: no transaction by one principal changes what another can withdraw beyond the pool economics the protocol implements
- Expected Immunefi impact: Critical - permanent freezing of a position that can never be closed
- Fast validation: Snapshot every state variable `system-repay` touches, run `borrow` with the `ft` trait principal, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
