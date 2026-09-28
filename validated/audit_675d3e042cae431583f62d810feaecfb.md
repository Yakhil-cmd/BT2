### Title
Dust-gated `clean_bad_debt` can be indefinitely front-run by a permissionless third-party `supply` top-up that pushes residual collateral above `BAD_DEBT_USD_THRESHOLD` - ([File: contracts/controller/src/positions/liquidation/mod.rs])

### Summary
In the source bug, PartyA can cheaply flip a position's status (`OPENED` → `CLOSE_PENDING`) so that PartyB's `emergencyClosePosition` reverts, blocking an urgent closure. XOXNO Lending has the same shape in its permissionless bad-debt cleanup path: `clean_bad_debt` admits an account only when `is_socializable_bad_debt` holds — debt exceeds collateral **and** total collateral is at or below the fixed USD dust cap. A permissionless third-party `supply` into an existing supply position raises that collateral above the cap, causing the admission check to revert with `CannotCleanBadDebt`, and can be repeated on-demand by front-running every cleanup transaction.

### Finding Description
`process_clean_bad_debt` (`contracts/controller/src/positions/liquidation/mod.rs:196`) is permissionless — it only requires `caller.require_auth()` and that the flash guard is inactive — and delegates to `socialize_bad_debt` with `BadDebtGate::DustCapped`:

```rust
// contracts/controller/src/positions/liquidation/mod.rs
let admits = match gate {
    BadDebtGate::DustCapped => {
        is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
    }
    BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
};
assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);
```

The gate is `is_socializable_bad_debt` (`contracts/controller/src/positions/liquidation/curve.rs:25`):

```rust
total_debt > total_collateral && total_collateral <= Wad::from(BAD_DEBT_USD_THRESHOLD)
```

Meanwhile `supply` is open to arbitrary callers for top-ups: per the controller README authorization table, "a third-party `supply` may only top up hub assets the account already holds a supply position in" (`contracts/controller/README.md`, authorization section). An insolvent account that still holds a dust collateral position therefore satisfies the top-up precondition. Supplying that same hub asset increases `supply_positions` and hence `total_collateral` in `risk::calculate_account_risk_totals`, flipping the second conjunct of `is_socializable_bad_debt` to false. The attacker's `supply` and the victim-facing `clean_bad_debt` are two independent permissionless calls into the same account state — exactly the front-run/flip-state pattern of the source report.

Notes on scope:
- `supply` carries `#[when_not_paused]`, so the grief only works while the contract is unpaused — which is also when bad debt must be cleaned promptly.
- `check_bad_debt_after_liquidation` (`apply.rs`, called at `mod.rs:135`) shares the same dust-capped admission internally, but the standalone attacker-facing vector is `clean_bad_debt` vs. `supply`.

### Impact Explanation
Permissionless bad-debt socialization is the protocol's mechanism for writing insolvent debt into the supply index and deleting the dead account (INV-LIQ-04: collateral is reclassified as revenue, debt is written off, and the account plus NFT are atomically removed). While that cleanup is blocked, the insolvent account's debt continues accruing interest against the market's debt index and the shortfall against suppliers grows. The attacker can maintain the block for as long as they keep collateral above the $5 dust cap, converting a one-transaction cleanup into a permanently-reverting entrypoint. This is a temporary/griefing freeze of a required protocol operation rather than direct theft.

### Likelihood Explanation
Medium-low, bounded by economics:

- The attack is costly to sustain: every top-up donates real collateral (> `BAD_DEBT_USD_THRESHOLD` ≈ $5 per round) to the insolvent account, and any liquidator can seize that added collateral through `process_liquidation`, dropping the account back below the dust cap and reopening cleanup. The attacker must re-donate after each seizure.
- The owner-only `process_force_socialize_bad_debt` (`mod.rs:246`) bypasses the dust cap entirely, so governance retains a workaround — reducing this from permanent to temporary blockage.
- Preconditions are cheap to meet: the insolvent account already holds the dust collateral position (that is precisely what makes it a cleanup candidate), and only `caller` auth plus a token transfer are needed to supply.

### Recommendation
Make the dust-capped admission robust against last-moment collateral changes:

1. In `socialize_bad_debt`, evaluate `is_socializable_bad_debt` against collateral that counts only positions the account held before some earlier state, or
2. Simpler and consistent with the existing gate structure: allow `clean_bad_debt` to net out the dust itself — i.e., run `execute_bad_debt_cleanup` regardless of the collateral level once `total_debt > total_collateral` and collateral is below a higher bound, since cleanup already reclassifies *all* remaining collateral as revenue, so top-ups actually increase what suppliers recover; or
3. Restrict third-party `supply` top-ups when the target account is insolvent (`total_debt > total_collateral`), so an outside caller cannot push a cleanup candidate over the dust cap.

### Proof of Concept
1. Setup: account `A` is insolvent — it holds a small supply position worth $4 in hub asset `X` (≤ `BAD_DEBT_USD_THRESHOLD` ≈ $5) and debt in asset `Y` worth more than $4. Prices/indexes make `is_socializable_bad_debt(total_debt, total_collateral)` true.
2. Keeper/liquidator submits `clean_bad_debt(caller, A)`.
3. Attacker front-runs with `supply(caller: attacker, account_id: A, spoke_id: A's spoke, assets: [(X_key, amount)])` where `amount` is worth > $1 — allowed because `A` already holds a supply position in `X` (third-party top-up rule).
4. The pending `clean_bad_debt` now computes `total_collateral > BAD_DEBT_USD_THRESHOLD`, so `admits` is false and it reverts with `CollateralError::CannotCleanBadDebt` (`mod.rs:235`).
5. Even after a liquidator seizes the donated collateral (restoring the dust condition), the attacker repeats step 3 in the same block as the next cleanup attempt, keeping `clean_bad_debt` permanently front-runnable for as long as they fund it.

Files involved:
- `contracts/controller/src/positions/liquidation/mod.rs:196-243` — permissionless cleanup and the `DustCapped` gate.
- `contracts/controller/src/positions/liquidation/curve.rs:25-27` — `is_socializable_bad_debt` conjunct on `total_collateral <= BAD_DEBT_USD_THRESHOLD`.
- `contracts/controller/README.md` — documents that third-party `supply` may top up existing supply positions of another account.