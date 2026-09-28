### Title
Supply-index floor clamp leaves wiped-out suppliers phantom claims that drain future pool cash - (File: contracts/pool/src/interest.rs)

### Summary
`apply_bad_debt_to_supply_index` socializes unpaid debt by scaling the market's `supply_index` down, but clamps the result at `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`). When bad debt approaches or exceeds the total supplied value, the index is clamped **up** relative to the true write-down, so supply shares retain a positive claim with no backing. Any cash that later enters the market (e.g. repayments from surviving borrowers) can be withdrawn against these phantom claims via `withdraw` before honest residual claimants, so users claim more than the pool actually holds and later claimants get less than entitled. This is the same class as the referenced Wagmi issue: claims are computed from share growth without regard to the loss the position actually absorbed.

### Finding Description
In `contracts/pool/src/interest.rs:73-89`, `apply_bad_debt_to_supply_index` computes `remaining = total_supplied_value − min(bad_debt, total_supplied_value)`, derives `reduction_factor = remaining / total_supplied_value`, then sets `new_supply_index = max(supply_index * reduction_factor, SUPPLY_INDEX_FLOOR_RAW)` [1](#0-0) . When `bad_debt >= ~99.9%` of supplied value, the true post-loss index is below `RAY/1000` but is clamped **up**, leaving every supply share — including shares whose value was fully wiped — with a positive residual claim (`unscale_supply_floor > 0`).

The write-down is triggered permissionlessly: `clean_bad_debt` (collateral ≤ $5 WAD, debt > collateral) calls `seize` with `AccountPositionType::Borrow`, which runs `unscale_borrow_ceil_ray` → `apply_bad_debt_to_supply_index` → `burn_debt` [2](#0-1) . After the burn, `borrowed` is reduced but the residual supply claims remain.

Withdrawal only enforces `require_reserves` (cash ≥ payout), the utilization gate, and `require_supply_for_debt` — it never checks that claims are backed [3](#0-2) . So once any cash re-enters the market — repayments by other borrowers on the same book, `recapitalize` top-ups, or interest flows — the holder of a wiped position can call `withdraw` with `amount = i128::MAX` and extract real cash against economically worthless shares. The pool's own test suite demonstrates the exact drain: `test_raw_cache_floor_residual_can_consume_fresh_cash_without_supply_guard` and `test_raw_cache_seizure_residual_would_drain_fresh_cash_without_supply_guard` show a wiped-out claimant extracting an entire fresh deposit, leaving the honest supplier's claim unbacked [4](#0-3) .

Note the backing gate on `supply` blocks **new deposits** into an under-backed market (`backing_shortfall > 0` rejects), which closes the specific fresh-deposit vector — but it does not protect cash arriving through `repay`, `recapitalize`, or `net_settle`-adjacent flows that credit cash without minting claims.

### Impact Explanation
Theft of user funds / redistribution loss. After a near-total bad-debt event, aggregate supply claims exceed the market's true residual value because the floor clamp overstates the index. Cash subsequently credited to the market (other borrowers' repayments, recapitalization) is captured by whoever withdraws first — including the attacker whose defaulted debt caused the write-down and who still holds wiped supply shares. Later legitimate claimants receive less than their entitlement, or nothing.

### Likelihood Explanation
Medium. Requirements: (a) bad debt ≥ ~99.9% of a market's supplied value so the floor clamp engages — reachable because debt grows at up to 200% APR (`borrow_index` monotone) while supply grows slower after `reserve_factor` skimming, so interest alone can push a defaulted position's debt past supplied value; (b) the account eligible for `clean_bad_debt` (total collateral ≤ $5); (c) cash re-entering the market afterwards (surviving debt repaying, or a recapitalizer). An attacker can construct this deliberately: supply and borrow in the same market, hold dust collateral elsewhere, let interest accrue, then call `clean_bad_debt` and race to withdraw against the residual claim. The supply backing gate blocks the pure fresh-deposit variant, capping the severity below the original.

### Recommendation
When the write-down would push `supply_index` below `SUPPLY_INDEX_FLOOR_RAW`, proportionally deflate `supplied` (and `revenue`) shares alongside the index clamp so the residual claim equals the true remaining value — i.e. burn `supplied` by the factor `floor_index / computed_index` instead of clamping the index upward. Alternatively, track an explicit `unbacked_claims` offset so the floor-clamp residual is excluded from `resolve_withdrawal` payouts and from `require_reserves` eligibility.

### Proof of Concept
1. Attacker supplies `S` of token T and borrows near the utilization cap in T; keeps collateral value ≤ $5 in other markets (or lets a price move create it).
2. Time accrues: `borrow_index` compounds while `supply_index` grows slower (reserve factor), until attacker debt value ≥ 99.9% of `supplied * supply_index`.
3. Anyone calls `clean_bad_debt(account)`: `seize` runs `apply_bad_debt_to_supply_index`, clamping the index to `SUPPLY_INDEX_FLOOR_RAW` and burning the debt. Attacker's `S` shares keep `unscale_supply_floor(S) > 0` with zero backing (demonstrated verbatim in `contracts/pool/tests/interest.rs:430-494`, where the residual claim `alice_stranded > 0` after full wipeout).
4. A second borrower repays (or a `recapitalize` credits cash) → `cache.cash > 0`.
5. Attacker calls `withdraw` with `amount = i128::MAX`; `require_reserves` passes against the new cash and the phantom claim pays out real tokens, leaving honest suppliers' residual claims unbacked — exactly the "gross == deposit" drain asserted in the test.

### Citations

**File:** contracts/pool/src/interest.rs (L73-89)
```rust
pub(crate) fn apply_bad_debt_to_supply_index(cache: &mut Cache, bad_debt: Ray) {
    let total_supplied_value = cache.supplied().mul(cache.env(), cache.supply_index());

    if total_supplied_value == Ray::ZERO {
        return;
    }

    let capped = bad_debt.min(total_supplied_value);
    let remaining = total_supplied_value.checked_sub(cache.env(), capped);

    let reduction_factor = remaining.div_floor(cache.env(), total_supplied_value);
    let new_supply_index = cache
        .supply_index()
        .mul_floor(cache.env(), reduction_factor);

    cache.set_supply_index(new_supply_index.max(Ray::from(SUPPLY_INDEX_FLOOR_RAW)));
}
```

**File:** contracts/pool/src/ops/seize.rs (L23-28)
```rust
    match entry.side {
        AccountPositionType::Borrow => {
            let bad_debt = cache.unscale_borrow_ceil_ray(position);
            interest::apply_bad_debt_to_supply_index(&mut cache, bad_debt);
            cache.burn_debt(position);
        }
```

**File:** contracts/pool/src/ops/withdraw.rs (L111-119)
```rust
fn gate_and_debit(env: &Env, cache: &mut Cache, net_transfer: i128, skip_utilization_check: bool) {
    cache.require_reserves(net_transfer);

    if !skip_utilization_check {
        guards::require_utilization_below_max(env, cache);
    }
    guards::require_supply_for_debt(env, cache);
    cache.debit_cash(net_transfer);
}
```

**File:** contracts/pool/tests/interest.rs (L339-369)
```rust
        let stranded = cache.unscale_supply_floor(scaled_a);
        assert!(stranded > 0, "floor clamp leaves userA a phantom claim");
        assert_eq!(cache.cash(), 0, "empty market: no cash to extract yet");

        let c = stranded;
        let scaled_b = cache.calculate_scaled_supply(c);
        cache.mint_supply(scaled_b);
        cache.credit_cash(c);

        let b_claim = cache.unscale_supply_floor(scaled_b);
        assert_eq!(b_claim, c, "userB's honest claim equals their deposit");

        let (burn, gross) = cache.resolve_withdrawal(i128::MAX, scaled_a);
        cache.require_reserves(gross);
        cache.burn_supply(burn);
        cache.debit_cash(gross);

        assert!(gross > 0, "stranded position pays out non-zero");
        assert_eq!(
            gross, c,
            "userA drains exactly userB's fresh deposit out of the pool"
        );

        assert!(
            cache.cash() < b_claim,
            "pool cash ({}) can no longer cover userB's claim ({}): honest supplier lost funds",
            cache.cash(),
            b_claim
        );
        assert_eq!(cache.cash(), 0, "userA drained the pool to empty");
    });
```
