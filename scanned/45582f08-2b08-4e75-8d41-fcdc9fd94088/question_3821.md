# Q3821: refresh via supply-collateral-add: route a victim's mandatory payout through a principal that

## Question
Can an unprivileged attacker entering through `supply-collateral-add` (mainnet/contracts/market/v0-4-market.clar:1175), controlling vault share price at the moment of the deposit leg, drive `refresh` (mainnet/contracts/market/v0-market-vault.clar:171) — which rewrites `mask` and stamps `last-update` to `stacks-block-time` on every write — to route a victim's mandatory payout through a principal that always rejects delivery, breaking the invariant that a victim's outcome does not depend on whether an attacker transacted first in the same block, and cause protocol insolvency through uncollateralised debt?

## Target
- File/function: `mainnet/contracts/market/v0-market-vault.clar:171` -> `refresh`
- Entrypoint: `supply-collateral-add` (`mainnet/contracts/market/v0-4-market.clar:1175`), unprivileged and publicly callable
- Attacker controls: vault share price at the moment of the deposit leg
- Exploit idea: `refresh` rewrites `mask` and stamps `last-update` to `stacks-block-time` on every write. Reach it through `supply-collateral-add` and route a victim's mandatory payout through a principal that always rejects delivery.
- Invariant to test: a victim's outcome does not depend on whether an attacker transacted first in the same block
- Expected Immunefi impact: Critical - protocol insolvency through uncollateralised debt
- Fast validation: Run the baseline `supply-collateral-add` call, then the attacker-shaped one with vault share price at the moment of the deposit leg, and assert the attacker's net token balance change is zero or negative.
