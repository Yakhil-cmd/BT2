# Q2241: total-assets via redeem: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `redeem` (mainnet/contracts/vault/v0-vault-stx.clar:797), controlling `recipient`, drive `total-assets` (mainnet/contracts/vault/v0-vault-stx.clar:334) — which adds `(- debt borrowed)` as accrued interest that no token in the vault yet backs — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause permanent freezing of funds?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:334` -> `total-assets`
- Entrypoint: `redeem` (`mainnet/contracts/vault/v0-vault-stx.clar:797`), unprivileged and publicly callable
- Attacker controls: `recipient`
- Exploit idea: `total-assets` adds `(- debt borrowed)` as accrued interest that no token in the vault yet backs. Reach it through `redeem` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - permanent freezing of funds
- Fast validation: Snapshot every state variable `total-assets` touches, run `redeem` with `recipient`, recompute the invariant off-chain from the snapshot, and assert it matches the on-chain result.
