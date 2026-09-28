### Title
Bad-debt supply-index floor clamp resurrects wiped supplier shares, letting stale claims drain fresh deposits - ([File: contracts/pool/src/interest.rs])

### Summary
CVE-2017-13791 is a WebKit memory-corruption/use-after-free bug: an object logically destroyed is still reachable and its reuse corrupts state. The analog in XOXNO Lending is a **dangling supply claim**: when bad debt exceeds the market's total supplied value, `apply_bad_debt_to_supply_index` drives the reduction factor to zero but then clamps `supply_index` up to `SUPPLY_INDEX_FLOOR_RAW` instead of letting it reach zero or zeroing supplier shares. Suppliers whose claims were economically wiped still hold nonzero scaled shares, and at the floored index `unscale_supply_floor` values those shares above zero. After a fresh deposit adds real cash, the phantom claim withdraws actual tokens, exactly replicating a use-after-free: destroyed state (the wiped claim) is reused against live memory (the new deposit).

### Finding Description
In `contracts/pool/src/interest.rs`, `apply_bad_debt_to_supply_index` computes:

```text
capped    = min(bad_debt, total_supplied_value)
remaining = total_supplied_value - capped          // can be 0
factor    = remaining / total_supplied_value       // 0 on wipeout
new_index = supply_index * factor                  // 0
index     = max(new_index, SUPPLY_INDEX_FLOOR_RAW) // clamped UP to RAY/1000
```

The clamp exists to avoid a zero divisor in `calculate_scaled_supply` (division by `supply_index`), but it means `scaled_shares * index > 0` for every pre-existing supply share even though the bad debt consumed 100% of supplied value. This is reached permissionlessly via `clean_bad_debt(account_id)` → `process_clean_bad_debt` → `clean_bad_debt_standalone` → `socialize_bad_debt` (`BadDebtGate::DustCapped`, i.e. `debt > collateral && collateral <= BAD_DEBT_USD_THRESHOLD` at `contracts/controller/src/positions/liquidation/curve.rs:25-27`) → `execute_bad_debt_cleanup` → `pool_seize_positions_call`, or via `liquidate` → `check_bad_debt_after_liquidation`. The pool seize op burns the insolvent account's shares and calls `apply_bad_debt_to_supply_index` with the residual debt; when that residual exceeds the *remaining market-wide* supplied value, every other supplier's shares are wiped economically but not structurally.

`contracts/pool/tests/interest.rs:372-428` (`test_raw_cache_floor_clamp_strands_claim_without_supply_guard`) proves the mechanics: with `old_scaled = 1000 RAY` shares and `bad_debt = 5000 RAY` value, the index clamps to `SUPPLY_INDEX_FLOOR_RAW`, `unscale_supply_floor(old_scaled) > 0`, a fresh supplier deposits cash, and `resolve_withdrawal(i128::MAX, old_scaled)` on the wiped position pays out exactly the fresh deposit — `gross == fresh_cash` — leaving pool cash unable to cover the fresh supplier's claim.

### Impact Explanation
Theft of user funds / protocol insolvency. Any holder of pre-wipeout supply shares (a wiped supplier, or an attacker who held dust supply shares in the affected (hub, token) book) can withdraw real tokens after the market is re-seeded. The wiped account's scaled shares are fungible supply shares — nothing in `withdraw`, `supply`, or `commit` distinguishes them from legitimate shares. The phantom claim drains subsequent deposits 1:1 until cash is exhausted, permanently impairing later suppliers.

### Likelihood Explanation
Requires a wipeout-scale bad-debt event: residual unpaid debt after liquidation/seizure must exceed the total remaining supplied value in that (hub, token) market. This is reachable only when a market is severely undercollateralized (deep insolvency, e.g. a sharp price move on a thinly-supplied book), and the dust-threshold gate on `clean_bad_debt` additionally caps the insolvent account's leftover collateral. However, the condition is a single unprivileged call away once the market state satisfies it (`clean_bad_debt` is permissionless; `liquidate` also triggers it via `check_bad_debt_after_liquidation`), and any attacker already holding dust supply in that book captures the value. Post-wipeout exploitation requires only a new deposit to arrive — which is likely since the market remains live and its index/params appear normal. Medium likelihood, high impact.

### Recommendation
In `apply_bad_debt_to_supply_index`, treat the wipeout case explicitly instead of clamping the index: when `capped >= total_supplied_value` (remaining value is zero), burn/zero the `supplied` and `revenue` share totals alongside the index reset, or store a market-level `wiped` flag / epoch so that shares minted before the wipeout cannot be unscaled afterward. The cleaner fix mirrors share-reset semantics: a fresh epoch at `supply_index = RAY` (or the floor) must start with `supplied == 0`, so `calculate_scaled_supply` never divides by a stale index and no dangling claim survives. Add a regression test asserting `unscale_supply_floor(pre_wipeout_shares) == 0` claimability after a full-wipeout `clean_bad_debt` followed by a new deposit.

### Proof of Concept
1. Market `(hub, USDC)` has suppliers with total scaled supply `S_old`; index `1.0 RAY`.
2. An account's position goes deeply insolvent such that residual debt `D` exceeds the market's total supplied value `V = S_old * index` (e.g. `D = 5 * V` as in the test).
3. Any address calls `controller.clean_bad_debt(account_id)` (dust-capped gate passes: `total_debt > total_collateral`, `total_collateral <= BAD_DEBT_USD_THRESHOLD`).
4. `pool_seize_positions_call` burns the insolvent account's shares and invokes `apply_bad_debt_to_supply_index(cache, D)`; `remaining = 0`, `factor = 0`, `supply_index` is clamped to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`), while `S_old` shares persist.
5. A new supplier calls `supply(hub_asset=USDC, amount = X)`; cash is credited at the floored index.
6. The holder of `S_old` (any pre-wipeout supplier, or an attacker holding dust) calls `withdraw` with a full-close amount; `resolve_withdrawal` burns `S_old` and pays `floor(S_old * SUPPLY_INDEX_FLOOR) > 0` in real tokens — withdrawing `X` worth of cash that was deposited by the fresh supplier.
7. The fresh supplier's own claim now exceeds pool cash: funds lost.

Confirmed mechanically by `contracts/pool/tests/interest.rs:372-428` and by the clamp at `contracts/pool/src/interest.rs:73-89`; the permissionless entrypoint is `process_clean_bad_debt` at `contracts/controller/src/positions/liquidation/mod.rs:196-200` with admission via `is_socializable_bad_debt` at `contracts/controller/src/positions/liquidation/curve.rs:25-27`.

One uncertainty: whether the pool-side `seize` op passes `bad_debt` large enough to exceed *total* supplied value in a single call, or applies it per-entry — I was unable to read `contracts/pool/src/ops/seize.rs` in full; the per-call `capped = min(bad_debt, total_supplied_value)` logic still allows a wipeout whenever residual debt dominates the book, which is precisely what the existing unit test exercises directly on the cache.