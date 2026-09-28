### Title
Bad-debt wipeout clamps `supply_index` up to `RAY/1000` floor, resurrecting phantom supplier claims that drain future deposits - ([File: contracts/pool/src/interest.rs](contracts/pool/src/interest.rs))

### Summary
When bad debt equals or exceeds the total supplied value, `apply_bad_debt_to_supply_index` correctly computes a wiped-out index near zero, but then applies `.max(SUPPLY_INDEX_FLOOR_RAW)`, forcing `supply_index` back up to `RAY/1000`. Every wiped-out supplier's stored shares therefore still resolve to a positive token claim (≈1/1000 of their pre-wipe value) that is backed by nothing. Once any new depositor supplies tokens to the market, a wiped supplier can call `withdraw` and receive real tokens funded by the fresh deposit — theft of user funds.

### Finding Description
`apply_bad_debt_to_supply_index` (`contracts/pool/src/interest.rs:73-89`) computes:

```rust
let capped = bad_debt.min(total_supplied_value);
let remaining = total_supplied_value.checked_sub(cache.env(), capped);
let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
let new_supply_index = cache.supply_index().mul_floor(cache.env(), reduction_factor);
cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
```

When `bad_debt >= total_supplied_value`, `remaining = 0`, `reduction_factor = 0`, and the economically correct index is 0 — every supply share is worthless. Instead, the `.max(SUPPLY_INDEX_FLOOR_RAW)` clamp (defined in `common/src/constants/pool.rs` as `RAY/1000`) writes `RAY/1000`, which is **larger** than the correct 0 and independent of how large the original index was. Share balances are untouched, so `unscale_supply_floor(scaled)` still returns a positive amount for every pre-wipe supplier.

The dedicated regression test `test_raw_cache_floor_clamp_strands_claim_without_supply_guard` (`contracts/pool/tests/interest.rs:372-427`) demonstrates the exact exploit chain: a wiped position retains `stranded > 0` claim; `require_reserves` only masks it while `cash == 0`; after a fresh supplier deposits `fresh_cash`, the wiped supplier's `resolve_withdrawal(i128::MAX, old_scaled)` succeeds with `gross == fresh_cash`, leaving `cash < fresh_claim` — the new depositor's claim is now unbacked.

Reachability is permissionless: `clean_bad_debt(caller, account_id)` is open to any caller when the account's ceil debt exceeds half-up collateral and collateral ≤ $5 (docs/reference/formulas.md §Bad debt; `is_socializable_bad_debt`), and the subsequent `withdraw` by the wiped supplier is an ordinary user call. Any unprivileged user can also create the bad-debt state on their own account: supply, borrow, let the position go insolvent below the $5 dust threshold, call `clean_bad_debt`, wait for any new supplier, then withdraw.

The clamp also misfires on *partial* wipeouts whose true index lands below `RAY/1000`: any reduction factor that would push the index under the floor is clamped back up, inflating all suppliers' claims relative to what the socialized loss actually backs — the same phantom-claim effect at smaller magnitude.

### Impact Explanation
Permanent protocol insolvency and theft of user funds. After a full bad-debt cleanup, the market's `cash` is near zero but supplier claims are resurrected at ≈0.1% of their former value. The first `withdraw` executed after any new `supply` transfers real tokens to a supplier whose claim is unbacked; the new depositor's funds are permanently impaired. This scales linearly with fresh deposit volume and repeats for every pre-wipe supplier.

### Likelihood Explanation
Requires a market to reach the socializable bad-debt state (debt > collateral, collateral ≤ $5 for the permissionless path — or any size via owner `force_socialize_bad_debt`), then one later deposit into that market. Small dust bad-debt events are a routine outcome of liquidation tail risk, so the condition is expected to occur in operation; the exploit then needs only an ordinary `supply` followed by `withdraw`. The unit test proves the arithmetic deterministically. Severity High.

### Recommendation
Do not clamp the post-write-down index upward. If a zero index must be avoided for liveness reasons, instead zero out the supply base atomically (e.g., migrate `supplied`/`revenue` shares to zero alongside the index, or record a "wiped" flag that makes `unscale_supply*` return 0), so no shares retain a claim the cash cannot back. At minimum, set the index to `new_supply_index` unclamped and gate withdrawals on it, or raise the floor only when `new_supply_index > 0` (i.e., only bind the floor to *partial* write-downs, never to a complete wipeout where `remaining == 0`).

### Proof of Concept
```text
1. Eve supplies 1,000 C to market M; Bob (or Eve via a second account) borrows
   against it until the market holds debt D with low collateral.
2. Price moves or accrual leave the borrower's collateral < $5 and < debt.
   Permissionless clean_bad_debt(caller, account_id) runs:
   - seize.rs calls apply_bad_debt_to_supply_index(cache, unscale_borrow_ceil_ray(debt))
   - bad_debt >= supplied * supply_index  → remaining = 0 → reduction_factor = 0
   - supply_index written as max(0, RAY/1000) = RAY/1000   ← bug
   - Eve's scaled_amount is unchanged.
3. Pool cash for M ≈ 0 (borrowed out). Alice supplies X tokens to M
   (supply mints shares at the floored index and credits cash).
4. Eve calls withdraw(amount = 0 /* all */):
   resolve_withdrawal pays unscale_supply_floor(eve_scaled) ≈ eve_shares × RAY/1000 > 0,
   require_reserves passes because Alice's X now sits in cash.
   Eve receives tokens funded by Alice's deposit.
5. Alice's claim exceeds remaining cash → theft/permanent insolvency
   (mirrors test_raw_cache_floor_clamp_strands_claim_without_supply_guard,
   contracts/pool/tests/interest.rs:372-427).
```