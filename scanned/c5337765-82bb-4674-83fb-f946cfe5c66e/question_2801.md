# Q2801: total-supply-preview via deposit: seize from a position that is solvent under the mask its o

## Question
Can an unprivileged attacker entering through `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763), controlling `recipient`, including a contract principal, drive `total-supply-preview` (mainnet/contracts/vault/v0-vault-stx.clar:363) — which adds the not-yet-minted `calc-treasury-lp-preview` to the live supply that both conversions price against — to seize from a position that is solvent under the mask its own operations were validated against, breaking the invariant that collateral leaving a borrower equals debt cleared scaled by the penalty, never more, and cause protocol insolvency?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:363` -> `total-supply-preview`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `recipient`, including a contract principal
- Exploit idea: `total-supply-preview` adds the not-yet-minted `calc-treasury-lp-preview` to the live supply that both conversions price against. Reach it through `deposit` and seize from a position that is solvent under the mask its own operations were validated against.
- Invariant to test: collateral leaving a borrower equals debt cleared scaled by the penalty, never more
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `deposit` call, then the attacker-shaped one with `recipient`, including a contract principal, and assert the attacker's net token balance change is zero or negative.
