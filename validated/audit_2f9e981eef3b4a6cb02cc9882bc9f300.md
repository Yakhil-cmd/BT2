### Title
Supply-index floor in bad-debt socialization leaves phantom supplier claims that steal recapitalized funds - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
When `clean_bad_debt` socializes a loss that meets or exceeds the market's total supplied value, `apply_bad_debt_to_supply_index` clamps `supply_index` up to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`) instead of zero. Suppliers' scaled shares are never burned, so they retain a residual floor-rounded claim (`supplied * RAY/1000 / RAY`) with no cash backing. The market then reads insolvent (`backing_shortfall > 0`), and the only permissionless repair path is `recapitalize`, which injects real tokens without minting or burning shares. The wiped-out holder can then `withdraw` and drain the recapitalized cash — an unprivileged theft path mirroring the availability→loss class of the report.

### Finding Description
`apply_bad_debt_to_supply_index` computes the surviving fraction of supply value, scales `supply_index` down, and applies `.max(SUPPLY_INDEX_FLOOR_RAW)` as the final step. On a full wipeout (`bad_debt >= total_supplied_value`), `reduction_factor` is zero, so the index is set to `RAY/1000`, not zero. Every supplier's `scaled` balance still unscales to `floor(scaled * RAY/1000 / RAY)` asset units — a phantom claim.

`guards::backing_shortfall` measures `unscale_supply_floor(supplied) − (cash + unscale_borrow_ceil(borrowed))`. After wipeout, `borrowed` is burned and `cash` is zero, so the shortfall equals the phantom claim; `require_backed_market` makes `supply` revert with `PoolInsolvent`, so fresh suppliers cannot silently fund the drain (the raw-cache tests `test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard` and `test_raw_cache_seizure_residual_would_drain_fresh_cash_without_supply_guard` demonstrate the drain mechanics once cash lands). `recapitalize`, however, exists precisely to repair this shortfall without minting shares: a recapitalizer (or a well-meaning keeper) posts tokens equal to the measured shortfall, after which `require_reserves`/`debit_cash` pass and the stranded holder's `withdraw` pays out real cash against shares that should have been worth zero.

Entrypoints (all unprivileged): `controller.clean_bad_debt(caller, account_id)` on a dust-threshold insolvent account triggers the index write-down; `controller.recapitalize(...)` / `pool.recapitalize` restores backing; `controller.withdraw` or `pool.withdraw` extracts the cash.

### Impact Explanation
Permanent loss of recapitalized funds and protocol insolvency: tokens donated to repair a wiped market are immediately claimable by holders of economically worthless residual shares. Until the phantom claims are withdrawn or burned, the market also cannot accept new supply (`PoolInsolvent`), so the book is frozen or drains each successive recapitalization. Effect: theft of user funds (the recapitalizer's) plus an unusable market.

### Likelihood Explanation
Requires a market where socialized bad debt reaches total supplied value — achievable whenever a permissionlessly cleanable dust account's debt exceeds remaining supply, or after seizure-based socialization of a heavily underwater book. The cleanup caller needs no privileges. The recapitalize→withdraw sequence is a normal, documented repair flow, so the theft triggers on the expected operational path rather than an exotic sequence. Medium: conditional on a near-total wipeout, but fully permissionless once reached.

### Recommendation
When the wipeout is total, burn the residual supply shares (or set `supply_index` to zero and handle `supplied`/`revenue` accordingly) instead of clamping to `SUPPLY_INDEX_FLOOR_RAW`. Alternatively, make `recapitalize`/`supply` first settle or escrow the floored residual claims so newly posted backing cannot be claimed by wiped positions, and make `withdraw` of floor-residual claims subordinate to `backing_shortfall` being zero after the withdrawal.

### Proof of Concept
The repo's own characterization tests demonstrate the mechanics end-to-end in `contracts/pool/tests/interest.rs` (lines ~298–369 and ~430–496):

1. Market has `supplied = 1_000_000 * RAY` scaled shares, `supply_index = RAY`, `cash = 0`.
2. A debt write-down larger than total supply arrives via `clean_bad_debt`/`seize_positions` → `apply_bad_debt_to_supply_index(&mut cache, Ray::from(2_000_000 * RAY))`.
3. `supply_index` clamps to `SUPPLY_INDEX_FLOOR_RAW`; `unscale_supply_floor(supplied)` returns `stranded > 0` — a live claim against zero cash.
4. A recapitalizer posts `stranded` units (`credit_cash`), making `backing_shortfall == 0`.
5. The stranded holder calls `resolve_withdrawal(i128::MAX, scaled)` → `require_reserves(gross)` passes → `debit_cash(gross)` pays out exactly the recapitalized `stranded` units; `cash` returns to 0.

The production `supply` path is blocked by `require_backed_market` (README: `supply` → `PoolInsolvent` when under-backed), so the theft is exercised through `recapitalize`, which intentionally posts cash against the measured shortfall without touching the phantom shares — confirming reachability through documented, unprivileged flows.

Uncertain: whether an attacker alone can force a total wipeout cheaply versus requiring an organic collapse; the residual-drain mechanics themselves are proven by the in-repo tests.