# Q3565: convert-to-shares-preview via accrue: reprice every other holder's collateral in the same transa

## Question
Can an unprivileged attacker entering through `accrue` (mainnet/contracts/vault/v0-vault-stx.clar:835), controlling the block time at which accrual is first triggered in a block, drive `convert-to-shares-preview` (mainnet/contracts/vault/v0-vault-stx.clar:308) — which returns u0 outright when `total-assets-preview` is non-zero and supply is zero, minting nothing for a real deposit — to reprice every other holder's collateral in the same transaction that profits from it, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause direct theft of user funds at rest or in motion?

## Target
- File/function: `mainnet/contracts/vault/v0-vault-stx.clar:308` -> `convert-to-shares-preview`
- Entrypoint: `accrue` (`mainnet/contracts/vault/v0-vault-stx.clar:835`), unprivileged and publicly callable
- Attacker controls: the block time at which accrual is first triggered in a block
- Exploit idea: `convert-to-shares-preview` returns u0 outright when `total-assets-preview` is non-zero and supply is zero, minting nothing for a real deposit. Reach it through `accrue` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - direct theft of user funds at rest or in motion
- Fast validation: In `local-testing/tests` on a local fork, drive `accrue` with the block time at which accrual is first triggered in a block, then read `convert-to-shares-preview` state before and after in the same block and assert the two sides of the invariant are equal.
