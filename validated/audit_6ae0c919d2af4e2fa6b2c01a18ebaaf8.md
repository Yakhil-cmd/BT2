### Title
Interest accrual can push utilization past `max_utilization`, freezing all non-liquidation withdrawals and revenue claims - (File: contracts/pool/src/guards.rs)

### Summary
The pool enforces `UtilizationAboveMax` on every non-liquidation withdrawal, borrow, net settlement, and `claim_revenue`, but the gate is evaluated **after** interest accrual. Since `borrow` only checks utilization at mint time, ordinary interest accrual can drift utilization above `params.max_utilization`. Once crossed, every exit path available to suppliers reverts until a borrower voluntarily repays — there is no self-correcting mechanism, because no operation that reduces debt is forced to run and liquidations may not be economically triggered (accounts can remain healthy while utilization stays above the cap).

### Finding Description
`require_utilization_below_max` in `contracts/pool/src/guards.rs` computes `borrowed * borrow_index` (ceiled) over `supplied * supply_index` (floored) and panics with `UtilizationAboveMax` when the ratio exceeds `max_utilization` [1](#0-0) . `ops::withdraw::gate_and_debit` invokes this guard on every non-liquidation, non-empty-close withdrawal [2](#0-1) . The docs confirm the same gate covers `claim_revenue` and `net_settle` [3](#0-2) .

The invariant documentation itself acknowledges the gap: "Accrual and bad-debt writeoff can exceed the ceiling; it is not a market-wide bound maintained by every operation" [4](#0-3) . Because `global_sync` accrues interest before any mutation [5](#0-4) , the ceiled debt value grows monotonically while floored supply value grows more slowly, so utilization is a one-way ratchet absent repayments.

Reachable path for a single unprivileged address: `controller.borrow` with `--borrows (hub_id, debt_asset, X)` sized so utilization lands just below `max_utilization`, backed by a still-healthy collateral position in another market. Time then does the rest — no further attacker action is needed. Every subsequent `controller.withdraw`, `controller.claim_revenue`, or `pool.net_settle` on that market reverts.

### Impact Explanation
All supplier funds in the affected market are frozen: suppliers cannot withdraw any amount, and protocol revenue cannot be claimed (`claim_revenue` is gated too). The freeze persists until some borrower repays enough debt to push utilization back under the cap. If borrowers are undercollateralized or simply inactive, repayment may never occur — liquidation (`is_liquidation = true`) skips the utilization check but only retires debt for accounts with `HF < 1`; solvent borrowers' debt keeps the gate tripped indefinitely. This maps to temporary freezing of funds with a plausible path to indefinite duration.

### Likelihood Explanation
The trigger requires a market configured with `max_utilization < RAY` (the gate is skipped at `>= 1.0`) [6](#0-5) , utilization near the cap, and a borrow rate above the supply-growth rate — the normal regime for any well-utilized market. An attacker needs only one `supply` + `borrow` pair funded by their own collateral, both standard unprivileged entrypoints. Borrower non-repayment is common and costs the attacker nothing beyond opportunity cost of their collateral. Medium severity: real fund freezing, but bounded by the market's outstanding debt and reversible if any repayer or liquidation arrives.

### Recommendation
Exempt withdrawals (and `claim_revenue`) from `require_utilization_below_max`, or apply the gate only to the delta the operation adds to utilization — a withdrawal reduces supply value but never increases debt, so blocking exits does not protect solvency. Alternatively, evaluate the utilization gate against pre-accrual state, or add a withdrawal-only tolerance band above `max_utilization`. At minimum, ensure `net_settle` and `repay` remain reachable (they do) and document to suppliers that crossing the cap freezes exits until debt is retired.

### Proof of Concept
1. Market `M` listed with `max_utilization = 0.95 * RAY`, borrow APR > supply APY.
2. Attacker calls `controller.supply` collateral in market `C`, then `controller.borrow` on `M` sizing debt so `borrowed/supplied = 0.949` — passes the gate.
3. Advance ledger time; `global_sync` inside the next call accrues debt value to `0.951` of supply value.
4. Any supplier calling `controller.withdraw` (or owner calling `claim_revenue`) on `M` panics with `UtilizationAboveMax` (pool #127) at `guards.rs:31`, routed through `withdraw.rs:115`.
5. The state persists indefinitely unless a `repay`, `net_settle`, or `liquidate` reduces `borrowed` shares; an attacker holding solvent-but-indebted accounts has no incentive to repay.

Note: the general pattern "accrual can exceed the ceiling" is acknowledged in `docs/reference/invariants.md` (INV-UTIL commentary) and DoS.8 in the threat model mentions utilization limits rejecting actions; however, the concrete permanent-freeze consequence on withdrawals/revenue via passive accrual drift, and the fixability of it, are not explicitly treated as an accepted outcome there, which is why this is reported rather than dismissed.

### Citations

**File:** contracts/pool/src/guards.rs (L19-34)
```rust
pub(crate) fn require_utilization_below_max(env: &Env, cache: &Cache) {
    if cache.supplied() == Ray::ZERO || cache.params().max_utilization >= Ray::ONE {
        return;
    }

    let borrowed = cache.borrowed().mul_ceil(env, cache.borrow_index());
    if borrowed == Ray::ZERO {
        return;
    }
    let supplied = cache.supplied().mul_floor(env, cache.supply_index());
    assert_with_error!(
        env,
        supplied > Ray::ZERO && borrowed.div_ceil(env, supplied) <= cache.params().max_utilization,
        CollateralError::UtilizationAboveMax
    );
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

**File:** contracts/pool/README.md (L141-148)
```markdown
| `withdraw` | `AmountMustBePositive` (14) on a negative amount or fee, `WithdrawRoundsToZeroShares` (49), `WithdrawLessThanFee` (115), `InsufficientLiquidity` (112), `UtilizationAboveMax` (127) on non-liquidation calls, `PoolInsolvent` (123), `InternalError` (34) |
| `repay` | `AmountMustBePositive` (14), `RepayRoundsToZeroShares` (52), `MathOverflow` (33) |
| `net_settle` | `AmountMustBePositive` (14), `NetSettleRoundsToZeroShares` (50), `PoolInsolvent` (123), `InternalError` (34) |
| `seize_positions` | `AmountMustBePositive` (14), `InternalError` (34) |
| `flash_loan` | `AmountMustBePositive` (14), `FlashloanNotEnabled` (401), `InsufficientLiquidity` (112), `InvalidFlashloanReceiver` (412) for a non-Wasm receiver, `InvalidFlashloanRepay` (402) for a short allowance or a balance mismatch |
| `create_strategy` | `AmountMustBePositive` (14) on a negative amount, `StrategyFeeExceeds` (409), plus the whole `borrow` set — it mints debt through the same path |
| `recapitalize` | `AmountMustBePositive` (14) on a negative amount, `MathOverflow` (33) |
| `claim_revenue` | `UtilizationAboveMax` (127), `PoolInsolvent` (123), `OwnerNotSet` (32), `InternalError` (34) |
```

**File:** docs/reference/invariants.md (L187-188)
```markdown
Liquidation withdrawal skips the gate. Accrual and bad-debt writeoff can exceed
the ceiling; it is not a market-wide bound maintained by every operation.
```

**File:** contracts/pool/src/interest.rs (L20-33)
```rust
pub(crate) fn global_sync(env: &Env, cache: &mut Cache) {
    if !cache.needs_accrual() {
        return;
    }

    let mut remaining = cache.elapsed_ms();
    while let Some(nonzero) = NonZeroU64::new(remaining) {
        let chunk = nonzero.get().min(MAX_COMPOUND_DELTA_MS);
        accrue_chunk(env, cache, chunk);
        remaining = remaining.saturating_sub(chunk);
    }

    cache.mark_accrued();
}
```
