### Title
Supply index clamped up to `SUPPLY_INDEX_FLOOR_RAW` on wipeout leaves stranded claims that drain fresh deposits - (File: contracts/pool/src/interest.rs)

### Summary
`apply_bad_debt_to_supply_index` socializes unpaid debt by scaling the supply index down, but then clamps the result **up** to `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`). This is the same bug class as the Lyra finding: a stored value is capped/floored so it no longer reflects the true computed value, and downstream consumers (share-to-asset unscaling) operate on the inconsistent number. After a wipeout the true index should approach zero; instead the floor leaves every unburned supply share a residual claim backed by nothing. The repository's own tests demonstrate a wiped-out supplier then withdraws a fresh depositor's cash in full.

### Finding Description
In `contracts/pool/src/interest.rs:73-89`:

```rust
let capped = bad_debt.min(total_supplied_value);
let remaining = total_supplied_value.checked_sub(cache.env(), capped);
let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
let new_supply_index = cache.supply_index().mul_floor(cache.env(), reduction_factor);
cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
```

When `bad_debt >= total_supplied_value`, `reduction_factor` is zero and the correct index would be ~0, but the floor writes `RAY/1000`. Supply shares are **not** burned or reset — only the index moves — so `scaled_amount * SUPPLY_INDEX_FLOOR_RAW` remains a positive claim (`unscale_supply_floor` returns > 0). This is invoked from `seize::apply` (`contracts/pool/src/ops/seize.rs:24-28`) on the `Borrow` side, reached by the controller's liquidation / bad-debt cleanup path.

`contracts/pool/tests/interest.rs:317-370` (`test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard`) and `:372-428` and `:430-495` simulate exactly this: after the clamp, a wiped position's residual `resolve_withdrawal(i128::MAX, scaled)` yields `gross == fresh_deposit`, debiting pool cash that belongs to a new honest supplier.

### Impact Explanation
Theft of user funds / protocol insolvency. A supplier whose position was economically wiped out retains a phantom claim of `shares * RAY/1000`. Once any new deposit (or `recapitalize` contribution, or repaid cash) lands in the same market, the stranded holder can `withdraw` and extract real tokens pro-rata ahead of honest suppliers, leaving `cash < honest_claim` — a permanent loss borne by fresh suppliers.

### Likelihood Explanation
Reachable by unprivileged actors: anyone can be a supplier, and anyone can drive a position into bad debt and trigger `liquidate`/`clean_bad_debt` once HF < 1. Preconditions are demanding: bad debt must meet or exceed total supplied value in a market (a wipeout-level event, e.g. extreme price move or oracle-band jump plus an underwater borrower), and fresh cash must arrive afterward. The clamped index is also visible state, so the attack window is opportunistic rather than guaranteed — Medium likelihood at best.

### Recommendation
Do not clamp the socialized index upward. When bad debt consumes all supplied value, either set `supply_index` to a value that zeroes claims and reset `supplied`/`revenue` shares to zero, or explicitly burn all supply positions at wipeout. If the floor is kept to avoid a zero index (per the doc comment), the residual shares must be burned or the market must be tombstoned so `resolve_withdrawal`/`require_reserves` cannot pay out phantom claims.

### Proof of Concept
Provided in-repo: `contracts/pool/tests/interest.rs:317-370` — wipe a market with `apply_bad_debt_to_supply_index(2_000_000 * RAY)` against `supplied = 1_000_000 * RAY`, observe `supply_index == SUPPLY_INDEX_FLOOR_RAW` and `unscale_supply_floor(old_scaled) > 0`, then mint fresh supply + cash and show `resolve_withdrawal(i128::MAX, old_scaled)` returns `gross == fresh deposit`, leaving `cash < honest_claim`. The equivalent production path is: supply to a market → borrower position goes bad → liquidator calls `liquidate`/`clean_bad_debt` triggering `seize` (Borrow side) → floor clamp → victim supplies again (or another user does) → attacker calls `withdraw` on the stranded position and drains the new cash.

Caveat: the test names note "without supply guard," implying some guard may exist elsewhere in the supply/withdraw path; I could not confirm whether a check fully blocks withdrawal of floor-residual shares in production. If no such guard exists, this is a valid High-severity analog; if one exists, it should be verified it covers the post-wipeout residual-claim case.