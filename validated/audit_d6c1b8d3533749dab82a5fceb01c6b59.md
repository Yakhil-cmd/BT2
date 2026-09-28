### Title
Normal withdrawals are permanently blocked whenever market utilization is already above `max_utilization`, freezing supplier funds until third parties repay debt - ([File: contracts/pool/src/ops/withdraw.rs](contracts/pool/src/ops/withdraw.rs))

### Summary
The bug class in the external report is "a withdrawal path hardwired to one exit shape reverts while the underlying pool sits in a persistent state (Balancer proportional-exit)". XOXNO Lending has the same shape: `pool::withdraw` gates every non-liquidation exit on the *post-withdrawal* utilization being at or below `params.max_utilization`. Because a withdrawal can only raise utilization (it shrinks supply while debt is unchanged), once utilization crosses the cap — which suppliers cannot cause or cure — **no** supplier can exit through the normal path, even when the pool holds enough cash to pay them in full.

### Finding Description
`accounting` in `contracts/pool/src/ops/withdraw.rs:57-89` resolves the burn, then calls `gate_and_debit` (line 79). For normal withdrawals `gate_and_debit` runs `guards::require_utilization_below_max` (`contracts/pool/src/guards.rs:19-34`), which asserts `borrowed.div_ceil(supplied) <= max_utilization` after the burn.

Utilization = debt / supply. A withdrawal only decreases `supplied`, so the check is monotone against the user: if utilization is already above `max_utilization`, every `withdraw` amount — including a dust withdrawal of 1 unit — reverts with `UtilizationAboveMax`. States that push utilization over the cap without any supplier action:

1. **Interest accrual**: borrow index compounds every millisecond chunk while the supply index grows slower (reserve factor skim). A market sitting near `max_utilization` drifts past it on its own.
2. **Bad-debt write-down**: `seize_positions`/`clean_bad_debt` floors `supply_index` at `SUPPLY_INDEX_FLOOR_RAW` while `borrowed` may still be non-zero on the book (see `tests/test-harness/tests/pool_money_flow_audit.rs:319-321` where `wiped.supply_index` hits the floor with debt previously outstanding). The collapsed denominator makes `borrowed/supplied` explode, so the gate bricks all exits even though `recapitalize` may have restored cash.
3. **Price/rate reconfiguration by governance** is not needed — the unprivileged trigger is simply time or a permissionless `clean_bad_debt` call on a dust-insolvent account.

The only exits that skip the gate are `is_liquidation` legs and the `empty_close` footprint case (`withdraw.rs:78-79`) — neither helps an ordinary supplier. `require_reserves` would already fail honestly when cash is short; the utilization gate adds a *second*, stricter failure mode that fires even when `cash >= net_transfer`.

Path: `controller.withdraw` → `positions::supply::execute_withdrawal` (`contracts/controller/src/positions/supply.rs:217-251`) → `pool.withdraw` → `accounting` → `gate_and_debit` → `require_utilization_below_max` → revert.

### Impact Explanation
Temporary freezing of user funds. Suppliers cannot withdraw *at all* — not even amounts fully covered by idle `cash` — until unrelated borrowers voluntarily repay or a `recapitalize`/repayment brings utilization back under the cap. During a crash this is exactly when suppliers want out, mirroring the reported scenario where Balancer emphasized urgent withdrawal while the pool state blocked it. Duration is unbounded: it depends on third-party borrowers, who themselves have no incentive to repay quickly. This is stronger than a fail-closed liquidity check because `cash` may be ample; the gate is a solvency *ratio*, not a liquidity check.

### Likelihood Explanation
Moderate. No attacker action is required — normal interest accrual or one permissionless `clean_bad_debt` on a dust account suffices to cross the cap on a market configured near `max_utilization` (mainnet configs set values below `RAY`, e.g. ~95%). Once crossed, the freeze affects every supplier of that (hub, token) book simultaneously. It resolves only when the ratio recovers, so it is a transient, not permanent, freeze — consistent with Medium.

### Recommendation
Skip the utilization gate for withdrawals (or apply it only to the incremental utilization the withdrawal itself creates vs. letting exits proceed while `require_reserves` passes), or allow withdrawals up to the amount that keeps utilization at `max_utilization` rather than reverting when already above it. The `require_supply_for_debt` and `require_reserves` guards already prevent insolvent/under-collateralized cash drains; the utilization ceiling should bound *new risk* (borrow, strategy creation), not exits.

### Proof of Concept
1. Supplier S calls `controller.supply` for hub asset A (amount X); borrower B borrows so that `borrowed/supplied` sits just below `max_utilization`.
2. Time passes: `global_sync` accrues the borrow index faster than the supply index, pushing `borrowed/supplied` above `max_utilization` (alternatively, an unprivileged caller runs `clean_bad_debt` on a dust-insolvent account, writing `supply_index` down to `SUPPLY_INDEX_FLOOR_RAW`).
3. S calls `controller.withdraw(account_id, A, amount=1)`. Inside `pool.withdraw`, `gate_and_debit` invokes `require_utilization_below_max`; `borrowed.div_ceil(supplied) > max_utilization` → panic `UtilizationAboveMax`. The call reverts even though `cash` covers the withdrawal (`require_reserves` would pass).
4. Every subsequent `withdraw` by any supplier reverts identically until B repays — funds are frozen by a state S cannot influence.

Uncertain aspects I could not fully verify within tool limits: whether `clean_bad_debt`/`seize_positions` can leave a non-zero `borrowed` book with a floored `supply_index` in production flow (the harness test at `pool_money_flow_audit.rs:311-321` shows supply written down while debt is seized to zero, but a partial write-down leaving residual debt would trigger the same freeze); and whether any documented ADR intentionally accepts this freeze — if so it may be a documented choice rather than a defect.