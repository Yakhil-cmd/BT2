### Title
Permissionless supply top-up keeps an insolvent account above the bad-debt dust cap, indefinitely blocking `clean_bad_debt` - (File: contracts/controller/src/positions/liquidation/mod.rs)

### Summary
`clean_bad_debt` is the only permissionless way to socialize residual bad debt, and its admission gate (`BadDebtGate::DustCapped`) requires `total_collateral <= 5 WAD` in addition to insolvency. The controller's `supply` entrypoint explicitly allows third parties to top up an existing supply position on any account. An unprivileged attacker can therefore deposit a small amount of collateral into an already-existing supply leg of a deeply insolvent account, pushing `total_collateral` above the dust cap while `total_debt > total_collateral` still holds. Every subsequent `clean_bad_debt(account_id)` reverts with `CannotCleanBadDebt`, and the automatic post-liquidation cleanup (`check_bad_debt_after_liquidation`) fails the same gate — leaving unbacked debt permanently on the pool's books while the attacker keeps topping up.

### Finding Description
`supply` is permissionless for topping up existing positions: the doc on `contracts/controller/src/lib.rs:90-102` states "Third parties may only top up existing supply positions; owners and delegates may add assets", and delegates to `positions::process_supply` with no owner check for existing legs.

`clean_bad_debt` → `process_clean_bad_debt` → `clean_bad_debt_standalone` → `socialize_bad_debt(env, account_id, BadDebtGate::DustCapped)` in `contracts/controller/src/positions/liquidation/mod.rs:196-243`. The gate is: [1](#0-0) 

`is_socializable_bad_debt` requires `total_debt > total_collateral` **and** `total_collateral <= 5 WAD` (per `docs`/`math.md` bad-debt section). The same dust-capped gate is applied inside `liquidate` via `apply::check_bad_debt_after_liquidation` at `mod.rs:135`.

The only gate without the collateral cap is `process_force_socialize_bad_debt` (`mod.rs:246-249`), which is owner-only — an insolvent/abandoned account's owner cannot be relied on, so it does not provide a permissionless fallback.

The attacker path: an account ends a liquidation with, e.g., $3 of dust collateral and $50 of unbacked debt (eligible for cleanup). Before anyone calls `clean_bad_debt`, the attacker calls `supply(attacker, victim_account_id, spoke_id, [(existing_supply_hub_asset, >$2)])`. Now `total_collateral > 5 WAD`, so `socialize_bad_debt` panics with `CollateralError::CannotCleanBadDebt`. The attacker can repeat the top-up after each seizure restores eligibility, at a cost of roughly the dust-cap amount per round.

### Impact Explanation
Unbacked debt cannot be written down into the supply index (`pool::interest::apply_bad_debt_to_supply_index` runs only inside `execute_bad_debt_cleanup`, `bad_debt.rs:14-60`). While the gate is griefed, the bad debt keeps accruing borrow interest instead of being socialized, deepening the deficit borne by suppliers of that market. The account also cannot be removed (`remove_account_and_burn_nft` is only reached through cleanup). Impact class: sustained deferral of insolvency recognition — protocol insolvency grows and cleanup of unclaimed losses is temporarily frozen for as long as the attacker funds it.

### Likelihood Explanation
Likelihood is moderate: the attack requires the insolvent account to already hold at least one supply position (a dust leg is exactly what the dust cap is designed around, so this is the common case), and requires the attacker to sacrifice real collateral each round because every top-up is itself seizable by the next `liquidate`. The defense is economically self-limiting — each blocking deposit is donated to liquidators and the protocol — but there is no mechanism that makes continued blocking impossible, only costly.

### Recommendation
Compute the dust-cap eligibility on the collateral *excluding* positions added after the account became insolvent, or simpler: have `execute_bad_debt_cleanup`'s gate use the collateral measured at the time debt was incurred (e.g., record a per-account "cleanup-eligible collateral" snapshot updated only by owner-authorized actions). Alternatively, allow `clean_bad_debt` to proceed whenever `total_debt > total_collateral` and the collateral excess over the dust cap consists solely of third-party top-ups — e.g., by capping countable collateral at what the post-liquidation seizure already validated.

### Proof of Concept
1. Victim account is liquidated; residual state: debt $50 USDC-backed, dust supply leg worth $3 (`total_collateral = 3 WAD < 5 WAD`, `total_debt > total_collateral`) — `is_socializable_bad_debt` is true.
2. Attacker calls `controller.supply(attacker, victim_id, spoke_id, [(hub_asset_of_existing_leg, 3_000_000)])` — allowed per `lib.rs:91` since the leg already exists.
3. Any caller calls `controller.clean_bad_debt(caller, victim_id)` → `calculate_account_risk_totals` now returns `total_collateral ≈ 6 WAD` → `BadDebtGate::DustCapped` check fails → `panic CannotCleanBadDebt` (`mod.rs:229-235`).
4. A liquidator repays the collateral-backed quote and seizes the attacker's deposit; if the residual collateral again lands ≤ 5 WAD, attacker repeats step 2. Cleanup never executes while the attacker continues, and the $50 unbacked debt accrues interest against the supply index unwritten-down.

Note: this conclusion relies on the documented supply-top-up semantics at `lib.rs:90-102` and the dust-gate at `mod.rs:203-235`; I did not fully verify `process_supply`'s internal authorization checks or whether interest accrual alone can eventually push `total_collateral` back under the cap without further attacker action (index growth raises, not lowers, collateral value, so it cannot self-heal — the collateral only shrinks via seizure).

### Citations

**File:** contracts/controller/src/positions/liquidation/mod.rs (L229-235)
```rust
    let admits = match gate {
        BadDebtGate::DustCapped => {
            is_socializable_bad_debt(totals.total_debt, totals.total_collateral)
        }
        BadDebtGate::InsolventOnly => totals.total_debt > totals.total_collateral,
    };
    assert_with_error!(env, admits, CollateralError::CannotCleanBadDebt);
```
