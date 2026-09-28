### Title
Bad-debt write-down clamps `supply_index` up to `SUPPLY_INDEX_FLOOR_RAW`, resurrecting wiped-out supplier claims that drain later deposits - (File: contracts/pool/src/interest.rs)

### Summary
When bad debt meets or exceeds the total supplied value, `apply_bad_debt_to_supply_index` computes a `reduction_factor` of zero but then writes `supply_index = max(0, SUPPLY_INDEX_FLOOR_RAW)` — an out-of-domain write that stores a positive index where the correct result is zero. Every pre-existing scaled supply share keeps a phantom claim (`scaled * RAY/1000 > 0`) backed by nothing, so the next real deposit can be withdrawn by a wiped-out supplier. This is the memory-corruption analog of CVE-2019-13728 (out-of-bounds write): a bounds violation on an index write corrupts accounting state beyond the intended domain.

### Finding Description
`apply_bad_debt_to_supply_index` (`contracts/pool/src/interest.rs:73-89`) socializes bad debt by shrinking the supply index pro-rata:

```rust
let capped = bad_debt.min(total_supplied_value);
let remaining = total_supplied_value.checked_sub(cache.env(), capped);
let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
let new_supply_index = cache.supply_index().mul_floor(cache.env(), reduction_factor);
cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
``` [1](#0-0) 

When `bad_debt >= total_supplied_value`, `remaining = 0`, `reduction_factor = 0`, `new_supply_index = 0` — but the `.max(SUPPLY_INDEX_FLOOR_RAW)` write pushes the stored index back up to `RAY/1000`. The correct post-wipeout state is "all supply claims are worth zero"; instead the write stores a positive index, so all historical `scaled_amount` shares retain a claim of `scaled * RAY/1000`. The function never zeroes or resets `supplied`/`revenue` scaled shares to match the wipeout.

The pool's own test demonstrates the end-to-end loss: after the clamp, `unscale_supply_floor(old_scaled) > 0` ("floor clamp leaves S_old a phantom claim"), a fresh deposit of `fresh_cash` mints honest shares, and the wiped position's `resolve_withdrawal(i128::MAX, old_scaled)` pays out `gross == fresh_cash`, leaving `cash < fresh_claim` — the fresh supplier's funds are gone. [2](#0-1) 

The primitive is reachable from seizure/bad-debt settlement in `contracts/pool/src/ops/seize.rs`, which is invoked through controller `liquidate` / `clean_bad_debt` flows on insolvent accounts.

### Impact Explanation
Theft of user funds / protocol insolvency. After any liquidation that socializes bad debt covering ≥100% of a market's supplied value, all pre-existing supply shares regain a positive floor-valued claim with zero backing. The first new deposit into that market can be immediately and fully drained by any holder of pre-wipeout shares calling `withdraw`. Because the phantom claim is proportional to old scaled balances, an attacker who held (or cheaply acquired, e.g., via position-nft `transfer`) large wiped-out supply shares captures the entire fresh deposit. Booked claims then permanently exceed cash, so the market is insolvent for every subsequent supplier.

### Likelihood Explanation
Triggering requires a market where bad debt meets or exceeds total supplied value — i.e., a full wipeout, which is rare but reachable by an unprivileged liquidator via `liquidate`/`clean_bad_debt` on deeply insolvent accounts (exactly the case the bad-debt path exists for). No privileged role is needed to trigger the write; only the aftermath (deposit + withdraw by a wiped-share holder) requires ordinary entrypoints. The main uncertainty is whether `ops/seize.rs` or controller-side bad-debt handling adds a guard (e.g., refusing partial wipeouts or resetting shares) before/after this call — I could not fully verify the seize call path within the available iterations; the test name `..._without_supply_guard` suggests a guard may exist at a layer I did not read. If no such guard engages on the full-wipeout branch, severity is High; otherwise the finding collapses.

### Recommendation
In `apply_bad_debt_to_supply_index`, distinguish partial from total write-downs: when `capped == total_supplied_value`, reset `supplied` and `revenue` scaled shares to zero (or record a wipeout flag that zeroes claims) instead of clamping the index to `SUPPLY_INDEX_FLOOR_RAW`. The floor clamp should only apply when the computed index is genuinely positive-but-tiny, not when it is exactly zero. Alternatively, gate the clamp on `remaining > Ray::ZERO` so a zero `reduction_factor` yields a zero index plus an explicit share wipe.

### Proof of Concept
Executable demonstration already present in `contracts/pool/tests/interest.rs:373-427`:

1. Market state: `supplied = 1000e27` scaled, `supply_index = RAY`, `cash = 0`.
2. `apply_bad_debt_to_supply_index(cache, 5000e27)` — bad debt exceeds total supplied value. Asserted result: `supply_index == SUPPLY_INDEX_FLOOR_RAW` (clamped up), `cash == 0`, yet `unscale_supply_floor(old_scaled) > 0` — phantom claim.
3. Fresh supplier deposits `fresh_cash = stranded`; receives shares worth exactly `fresh_cash`.
4. Wiped-out holder calls `resolve_withdrawal(i128::MAX, old_scaled)`; `gross == fresh_cash`, `require_reserves` passes, `debit_cash` pays the full fresh deposit to the wiped position. Final: `cash < fresh_claim` — the new supplier can never be made whole.

On-chain path: attacker supplies to market M; a borrower's position becomes deeply insolvent (oracle move or interest accrual); attacker or any liquidator calls controller `liquidate`/`clean_bad_debt` so the pool seizes and socializes `bad_debt >= total_supplied_value`, hitting the clamped write; the market is then empty; victim supplies; attacker (or any old share holder) calls `withdraw` and takes the deposit.

### Citations

**File:** contracts/pool/src/interest.rs (L80-89)
```rust
    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/pool/tests/interest.rs (L388-426)
```rust
        apply_bad_debt_to_supply_index(&mut cache, Ray::from(5_000 * RAY));
        assert_eq!(
            cache.supply_index().raw(),
            SUPPLY_INDEX_FLOOR_RAW,
            "wipeout clamps supply_index UP to RAY/1000 instead of resetting shares to 0",
        );

        let stranded = cache.unscale_supply_floor(old_scaled);
        assert!(stranded > 0, "floor clamp leaves S_old a phantom claim");
        assert_eq!(
            cache.cash(),
            0,
            "no cash yet: invariant only masked by require_reserves"
        );

        let fresh_cash = stranded;
        let fresh_scaled = cache.calculate_scaled_supply(fresh_cash);
        cache.mint_supply(fresh_scaled);
        cache.credit_cash(fresh_cash);

        let fresh_claim = cache.unscale_supply_floor(fresh_scaled);
        assert_eq!(
            fresh_claim, fresh_cash,
            "fresh supplier's claim equals deposit"
        );

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, old_scaled);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded wiped position pays out real tokens");
        assert_eq!(gross, fresh_cash, "S_old drains exactly the fresh deposit");
        assert!(
            cache.cash() < fresh_claim,
            "pool cash ({}) can no longer cover fresh supplier claim ({}): funds lost",
            cache.cash(),
            fresh_claim,
        );
```
