# Q5293: calc-principal-ratio-reduction via deposit: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `deposit` (mainnet/contracts/vault/v0-vault-stx.clar:763), controlling `recipient`, including a contract principal, drive `calc-principal-ratio-reduction` (mainnet/contracts/vault/v0-vault-stx.clar:191) — which reduces scaled principal proportionally to an amount over total debt — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that one borrower's loss is not charged to suppliers beyond the socialization the design intends, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:191` -> `calc-principal-ratio-reduction`
- Entrypoint: `deposit` (`mainnet/contracts/vault/v0-vault-stx.clar:763`), unprivileged and publicly callable
- Attacker controls: `recipient`, including a contract principal
- Exploit idea: `calc-principal-ratio-reduction` reduces scaled principal proportionally to an amount over total debt. Reach it through `deposit` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: one borrower's loss is not charged to suppliers beyond the socialization the design intends
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `deposit` with `recipient`, including a contract principal, then read `calc-principal-ratio-reduction` state before and after in the same block and assert the two sides of the invariant are equal.
