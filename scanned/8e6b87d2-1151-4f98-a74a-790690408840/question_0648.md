# Q0648: receive-tokens via collateral-remove: route a victim's mandatory payout through a principal that

## Question
Does `collateral-remove` (mainnet/contracts/market/v0-4-market.clar:1107) let an unprivileged attacker who controls the set of assets held reach `receive-tokens` (mainnet/contracts/market/v0-market-vault.clar:256) in a state where it route a victim's mandatory payout through a principal that always rejects delivery? Given that it pulls an asset from a named account, the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block breaks and the result is temporary freezing of funds.

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:256` -> `receive-tokens`
- Entrypoint: `collateral-remove` (`mainnet/contracts/market/v0-4-market.clar:1107`), unprivileged and publicly callable
- Attacker controls: the set of assets held
- Exploit idea: `receive-tokens` pulls an asset from a named account. Reach it through `collateral-remove` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: High - temporary freezing of funds
- Fast validation: Fuzz the set of assets held across its boundary values through `collateral-remove` in simnet and assert `receive-tokens` never returns a value that breaks the invariant.
