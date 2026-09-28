### Title
Bad-debt wipeout clamps the supply index up to a floor, leaving wiped suppliers a phantom claim that drains later depositors' cash — (File: contracts/pool/src/interest.rs)

### Summary

The mapped bug class (a resource "larger than intended" leaking value it should not hold) lands on the supply-index write-down in `apply_bad_debt_to_supply_index`. When socialized bad debt meets or exceeds the market's total supplied value, the index is not driven to zero — it is clamped *up* to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`). Surviving supply shares therefore retain a positive floor claim — a "claim buffer" strictly larger than intended — even though the socialization declared their value fully destroyed. That residual claim is payable in real tokens and can consume fresh deposits made after the wipeout.

### Finding Description

`apply_bad_debt_to_supply_index` in `contracts/pool/src/interest.rs:73-89`:

```rust
let capped = bad_debt.min(total_supplied_value);
let remaining = total_supplied_value.checked_sub(cache.env(), capped);
let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
let new_supply_index = cache.supply_index().mul_floor(cache.env(), reduction_factor);
cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
```

When `bad_debt >= total_supplied_value`, `remaining = 0`, `new_supply_index = 0`, and the `max` with `SUPPLY_INDEX_FLOOR_RAW` revives the index to a nonzero value. Every pre-existing scaled supply position then unscales to a positive token claim (`unscale_supply_floor` > 0) against a market whose backing was just declared fully destroyed. `contracts/pool/src/ops/seize.rs:24-28` invokes this path with `bad_debt = unscale_borrow_ceil_ray(position)`, the ceiling-rounded debt being burned — which can legitimately exceed `supplied * supply_index` when the wiped debt share count exceeds the market's supply share count (e.g., debt accrued over time, or supply drained by prior withdrawals/liquidations leaving `supplied` small relative to `borrowed`).

The in-repo raw-cache tests demonstrate the concrete drain (`contracts/pool/tests/interest.rs:317-369` and `373-428`): after the floor clamp, a stranded position holds `stranded > 0` claim; a fresh deposit `c` of that size is then fully extracted by the old position via `resolve_withdrawal`/`require_reserves`/`debit_cash`, leaving `cash < fresh_claim` — the new depositor's funds are gone.

Reachability: `clean_bad_debt` is permissionless (`contracts/controller/src/lib.rs:163-165`, `positions/liquidation/mod.rs:196-199`) once an account is insolvent with collateral ≤ the $5 dust gate; `liquidate` also triggers the same seize path post-cleanup. No privilege, upgrade, or oracle dishonesty is required — only a market where a wiped debt position's ceiled value ≥ total supplied value, which an attacker can engineer by being the residual holder of both sides (small supply, large debt gone insolvent via their own price-independent actions plus ordinary accrual).

### Impact Explanation

Theft of user funds / protocol insolvency. The floor clamp manufactures claims out of nothing: shares that should unscales to zero instead claim `shares * RAY/1000`. The first wiped holder to withdraw after any fresh `supply` lands in the market drains that fresh cash — a direct transfer of an honest depositor's principal to a position whose value was already socialized to zero. `invariants.md` documents that "the index floor can leave a shortfall" covered by `recapitalize`, but the residual-claim drain is not merely a shortfall — it is an actively payable phantom balance consuming later deposits, which is stronger than the documented recapitalization gap.

### Likelihood Explanation

Moderate-to-low likelihood, critical impact. It requires a wipeout where `bad_debt ≥ total_supplied_value` in a single (hub, token) book, i.e., a market whose supply side was nearly fully exited while debt remained — plausible in thin/deprecating spoke markets, and reachable through permissionless `clean_bad_debt`. The unit tests confirm the arithmetic on a raw cache; whether production ops add a guard that zeroes stranded claims could not be fully verified within the search budget (`require_reserves` in `ops/withdraw.rs` only checks cash ≥ gross, which the fresh deposit satisfies — it does not prevent the drain).

### Recommendation

On total wipeout (`bad_debt >= total_supplied_value`), burn all supply/revenue shares or record a per-position write-down flag so stranded shares unscale to zero, rather than clamping the index up to `SUPPLY_INDEX_FLOOR_RAW`. Alternatively, keep the floor but gate withdrawals: reject (or zero-pay) `resolve_withdrawal` for positions whose scaled shares predate a floor-clamped wipeout, e.g., by storing a wipeout epoch/generation counter on the market and on positions.

### Proof of Concept

1. Attacker supplies dust `S` of token T in hub H and borrows `D` of T against collateral in another asset (or engineers insolvency so `D`'s ceiled value ≥ `supplied * supply_index` while attacker also holds the surviving supply shares).
2. After the account becomes insolvent with collateral ≤ $5, attacker (or anyone) calls `controller::clean_bad_debt(caller, account_id)` → `seize::apply` → `apply_bad_debt_to_supply_index` → `supply_index` clamps to `RAY/1000`. Attacker's dust shares still unscale to a positive claim.
3. Victim calls `supply` depositing `c` of T into H (or attacker lures/awaits organic deposits, or uses `recapitalize` cash).
4. Attacker calls `withdraw` on their position; `resolve_withdrawal` pays `gross = stranded` which equals up to `c`, debiting `cash` to zero. Victim's claim is unbacked.

Reference: `contracts/pool/tests/interest.rs:317-369` (`test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard`) encodes exactly this sequence and asserts `cash == 0` after the stranded withdrawal.