Audit Report

## Title
Donated Cycles to CMC Bypass Rate Limiter and Understate `total_cycles_minted` via Saturating Subtraction in `ensure_balance` — (File: rs/nns/cmc/src/main.rs)

## Summary
The `ensure_balance` function in the Cycles Minting Canister computes `cycles_to_mint` as `cycles - canister_balance128()` using the `Cycles` type's saturating subtraction. Because `canister_balance128()` returns the CMC's total live balance — including cycles donated by any unprivileged caller via the management canister's `deposit_cycles` endpoint — an attacker who pre-funds the CMC can reduce `cycles_to_mint` to zero for subsequent ICP-to-cycles conversions. This silently bypasses the rate limiter and leaves `total_cycles_minted` understated, while ICP is still burned and cycles are still distributed to the target canister from the donated balance.

## Finding Description

**Root cause — saturating subtraction on `Cycles`:**

In `rs/types/cycles/src/cycles.rs`, the `Sub` implementation for `Cycles` is:
```rust
fn sub(self, rhs: Self) -> Self {
    Self(self.0.saturating_sub(rhs.0))
}
```
So `cycles - current_balance` returns `Cycles::zero()` whenever `current_balance >= cycles`.

**Vulnerable code path in `ensure_balance` (`rs/nns/cmc/src/main.rs`, lines 2306–2325):**
```rust
fn ensure_balance(cycles: Cycles, limiter_to_use: CyclesMintingLimiterSelector) -> Result<(), String> {
    let now = now_system_time();
    let current_balance = Cycles::from(ic_cdk::api::canister_balance128()); // total live balance
    let cycles_to_mint = cycles - current_balance;                           // saturating → 0 if balance ≥ cycles

    with_state_mut(|state| {
        limiter_to_use.check_and_add_cycles(state, now, cycles_to_mint)?;   // charged 0
        state.total_cycles_minted += cycles_to_mint;                         // incremented by 0
        Ok::<_, String>(())
    })?;

    let _minted_cycles = ic0_mint_cycles128(cycles_to_mint);                 // mints 0
    assert!(ic_cdk::api::canister_balance128() >= cycles.get());
    Ok(())
}
```

**Rate limiter check (`rs/nns/cmc/src/limiter.rs`, lines 34–56):**
```rust
pub fn check_and_add_cycles(&mut self, now: SystemTime, cycles_to_mint: Cycles, limit: Cycles) -> Result<(), String> {
    self.purge_old(now);
    let count = self.get_count();
    if count + cycles_to_mint > limit {   // 0 never exceeds limit
        return Err(...);
    }
    self.add(now, cycles_to_mint);        // adds 0 to the window
    Ok(())
}
```

When `cycles_to_mint = 0`, the condition `count + 0 > limit` is only true if the limiter was already at capacity from prior legitimate minting — the donated-cycles scenario resets the effective cost to zero, consuming none of the per-period budget.

**Call chain:** `process_top_up` → `deposit_cycles` → `ensure_balance` (lines 1985–2012, 2110–2138). The same path is taken for canister creation and cycles-ledger deposits via `do_mint_cycles` (line 2151).

**Why existing checks are insufficient:** The `assert!` at line 2323 only verifies the post-condition that the balance is sufficient; it does not verify that the correct amount was minted from ICP. There is no guard distinguishing "cycles already in balance from donations" from "cycles minted from ICP."

## Impact Explanation

**Rate-limiter bypass (High — significant NNS/CMC security impact with concrete protocol harm):** The rate limiter (`base_limiter`, limit ~150 Petacycles/hour as exercised in integration tests) is the sole on-chain mechanism throttling ICP-to-cycles conversion bursts. An attacker who donates `D` cycles to the CMC enables up to `D` cycles worth of ICP to be burned in a single period with zero rate-limiter consumption. Because cycles can be sourced from ckETH/ckBTC chain-fusion bridges or any canister that has accumulated cycles — sources entirely independent of the CMC's own limiter — the attacker does not need to have previously been subject to the same rate limit. This allows a large ICP holder to convert an unbounded amount of ICP to cycles in a single period, undermining the economic throttle protecting the ICP supply.

**`total_cycles_minted` understatement:** The public query `total_cycles_minted` (line 2327–2330) is used by governance and monitoring tooling to audit the ICP-to-cycles conversion rate. When cycles are distributed from the donated balance, this counter is not incremented, breaking the conservation invariant `total_cycles_minted ≈ Σ(ICP burned × rate)` and silently corrupting the audit trail.

## Likelihood Explanation

Any canister on any subnet can call `management_canister.deposit_cycles` targeting the CMC's canister ID with attached cycles — this is a standard, unprivileged inter-canister call requiring no governance majority, no threshold-crypto compromise, and no privileged access. The attacker's cost is the donated cycles themselves, which can be sourced from chain-fusion bridges (ckETH, ckBTC) without having previously been subject to the CMC rate limiter. The attack is repeatable: once the donated balance is exhausted, the attacker can re-donate. The attack requires no victim mistakes and no social engineering.

## Recommendation

Track the CMC's "minted-from-ICP" balance separately from its total live balance. Introduce a `cycles_held_from_minting: Cycles` field in `State` that is incremented by `cycles_to_mint` after each successful `ic0_mint_cycles128` call and decremented when cycles are sent out to a target canister. Use this field — not `canister_balance128()` — to compute `cycles_to_mint` in `ensure_balance`:

```rust
let cycles_to_mint = cycles.saturating_sub(state.cycles_held_from_minting);
```

This ensures that donated cycles do not reduce the amount that must be minted from ICP, preserving both the rate-limiter accounting and the `total_cycles_minted` invariant.

## Proof of Concept

1. Attacker's canister calls `management_canister.deposit_cycles({ canister_id: CMC_CANISTER_ID })` with `LARGE_CYCLES` attached — donating to the CMC. This is an unprivileged call available to any canister.
2. CMC's `canister_balance128()` is now `prior_balance + LARGE_CYCLES`.
3. Any user calls `notify_top_up` for `N` ICP (≡ `X` cycles, where `X ≤ LARGE_CYCLES`).
4. `ensure_balance(X)` runs: `cycles_to_mint = X - (prior_balance + LARGE_CYCLES) = 0` (saturating).
5. `check_and_add_cycles(state, now, 0)` — rate limiter not charged; `state.total_cycles_minted += 0`.
6. `ic0_mint_cycles128(0)` — no new cycles minted from ICP.
7. CMC sends `X` cycles to the target canister from its existing (donated) balance.
8. `burn_and_log` burns `N` ICP.
9. Steps 3–8 repeat for any number of users until `LARGE_CYCLES` is exhausted; the rate limiter never fires regardless of total ICP burned.

A deterministic integration test can reproduce this using the existing `state_machine_builder_for_nns_tests` framework (as used in `cmc_notify_top_up_rate_limited` at `rs/nns/integration_tests/src/cycles_minting_canister.rs:1644`): pre-seed the CMC with cycles via a simulated `deposit_cycles` call, then verify that repeated `notify_top_up` calls exceeding the 150P/hr limit all succeed and that `total_cycles_minted` does not reflect the distributed cycles.