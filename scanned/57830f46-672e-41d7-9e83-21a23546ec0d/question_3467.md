# Q3467: filter-u128 via borrow: reprice every other holder's collateral in the same transa

## Question
`filter-u128` (mainnet/contracts/registry/v0-egroup.clar:97) filters a 128-entry bucket list. Can an unprivileged caller of `borrow` (mainnet/contracts/market/v0-4-market.clar:1238), by choosing `receiver`, including a contract principal, use that to reprice every other holder's collateral in the same transaction that profits from it, violating the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block and producing protocol insolvency?

## Target
- File/function: `mainnet/contracts/registry/v0-egroup.clar:97` -> `filter-u128`
- Entrypoint: `borrow` (`mainnet/contracts/market/v0-4-market.clar:1238`), unprivileged and publicly callable
- Attacker controls: `receiver`, including a contract principal
- Exploit idea: `filter-u128` filters a 128-entry bucket list. Reach it through `borrow` and reprice every other holder's collateral in the same transaction that profits from it.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency
- Fast validation: Run the baseline `borrow` call, then the attacker-shaped one with `receiver`, including a contract principal, and assert the attacker's net token balance change is zero or negative.
