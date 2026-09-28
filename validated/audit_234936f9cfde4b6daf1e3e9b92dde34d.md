### Title
Borrower permanently blocks liquidation by dust-supplying a `no_seize` collateral asset - (File: contracts/controller/src/positions/liquidation/plan.rs)

### Summary
In XOXNO Lending, seizure in `liquidate` is strictly pro-rata across *every* supply position of the account, and `build_liquidation_plan` reverts with `SpokeAssetSeizureHalted` if any seized leg's listing has the `no_seize` flag. However, `no_seize` is not an entry-blocking flag: `require_can_supply` only enforces `FreezePolicy::BlockOnEntry` (paused/frozen) plus `is_collateralizable`. An unprivileged borrower whose account is liquidatable (HF < 1 WAD) can therefore `supply` a dust amount of a listed, collateralizable, `no_seize` asset — or frontrun a pending liquidation with that call — and every subsequent `liquidate` reverts, preventing liquidation entirely while the dust position exists.

### Finding Description
The JOJO report describes frontrunning `repay()`/`deposit()` with a small amount to push an account back over the liquidation boundary and block liquidation. In XOXNO, a dust `repay` cannot cross the WAD-precision HF boundary and `liquidate` accepts partial quotes, so that exact mechanic fails. The same bug class — a tiny deposit that vetoes liquidation — does exist via the halt-flag system.

`build_liquidation_plan` computes a pro-rata seizure over all supply positions and then enforces the seizure policy on each leg:

```rust
// contracts/controller/src/positions/liquidation/plan.rs:81-89
for entry in seized_collaterals.iter() {
    enforce_spoke_asset_flags(
        env, cache, account.spoke_id, &entry.hub_asset,
        FreezePolicy::SeizureLeg,
    );
}
```

`FreezePolicy::SeizureLeg` asserts `!sa.no_seize` and panics with `SpokeAssetSeizureHalted` (#318):

```rust
// contracts/controller/src/positions/mod.rs:273-275
FreezePolicy::SeizureLeg => {
    assert_with_error!(env, !sa.no_seize, SpokeError::SpokeAssetSeizureHalted);
}
```

Meanwhile, supply entry never consults `no_seize`. `require_can_supply` calls `require_listed_unhalted_config`, which applies `FreezePolicy::BlockOnEntry` — checking only `paused` and `frozen` — plus `is_collateralizable` (`contracts/controller/src/positions/mod.rs:188-227`). The controller README confirms the flag semantics: "`no_seize` | The liquidation seizure leg. This is the only flag that stops a seizure."

So when a listing is `no_seize = true` but still collateralizable and unpaused/unfrozen (a plausible state while governance ratchets flags during an incident, e.g., a depegging asset being made unseizable before being frozen — flags are independent and only tightenable), the asset remains freely supplyable. The protocol docs acknowledge the consequence — "one `no_seize` leg makes the entire liquidation fail" — but do not prevent an unprivileged account from manufacturing such a leg.

Attack path (all reachable by a single unprivileged address, the account owner):

1. Borrower holds an undercollateralized position; a price move makes `HF < 1 WAD` (liquidatable).
2. Borrower calls `supply(caller, account_id, spoke_id, [(hub_asset_no_seize, dust)])` — or does it earlier while still solvent. A third-party `supply` is restricted to topping up existing positions, but the owner supplies freely.
3. Any `liquidate(liquidator, account_id, payments, seize_mode)` reverts in `build_liquidation_plan` at the `SeizureLeg` check, regardless of payment size or `SeizeMode` (`Transfer` or `Credit` — both go through the same seizure plan).
4. `clean_bad_debt` also cannot help while the collateral position exists with debt, since the account isn't eligible (debt vs. collateral condition and dust threshold aside, the position simply cannot be liquidated; the no_seize leg stays stuck).
5. The borrower can even withdraw most collateral normally (exits are unaffected by `no_seize`) while keeping the dust `no_seize` leg as a standing veto, since the pro-rata plan iterates all remaining supply positions.

The borrower can toggle the shield at will: withdraw the dust leg to become liquidatable, re-supply it to re-arm. Cost is one dust deposit.

### Impact Explanation
A borrower can unilaterally and indefinitely immunize its account against liquidation. Liquidators cannot seize collateral, so the position's debt accrues interest while collateral falls, producing bad debt that is eventually socialized into supply indexes (protocol insolvency / loss to suppliers). This fits the accepted impact classes: permanent blocking of the liquidation mechanism leading to protocol insolvency.

### Likelihood Explanation
Requires a listed spoke asset that is simultaneously `is_collateralizable`, not `paused`, not `frozen`, and `no_seize`. Flag tightening is one-way and independent per flag (`set_spoke_asset_flags` ratchets each flag), so transient states with only `no_seize` set are reachable — particularly during exactly the stressed-market incidents where `no_seize` would be invoked and where liquidations cluster. An attacker can also pre-position the dust leg cheaply before its account becomes liquidatable. Cost of attack: negligible (dust). No privileged access, timing luck, or third-party cooperation needed — just one `supply` call.

### Recommendation
Block supply entry for `no_seize` listings: include `no_seize` in the entry-side check (e.g., extend `FreezePolicy::BlockOnEntry` or `require_can_supply` to assert `!sa.no_seize`), so accounts cannot add an unseizable collateral leg. Alternatively — and more robustly, since a listing can gain `no_seize` after users already hold it — change the liquidation plan to exclude `no_seize` legs from the pro-rata seizure (repayment quote computed against seizable collateral only) rather than reverting the whole liquidation.

### Proof of Concept
Conceptual sequence against the real entrypoints:

```text
// Setup: spoke asset NS listed, is_collateralizable=true, no_seize=true,
// paused=false, frozen=false (possible because flags ratchet independently).
// 1. Borrower supplies collateral C, borrows D.
supply(borrower, acc, spoke, [(C_key, amount)])
borrow(borrower, acc, [(D_key, amount)], None)

// 2. Price moves; get_health_factor(acc) < 1e18 → liquidatable.

// 3. Shield: borrower dust-supplies the no_seize asset.
supply(borrower, acc, spoke, [(NS_key, 1)])   // passes: BlockOnEntry checks only paused/frozen

// 4. Liquidator attempts seizure; reverts with SpokeAssetSeizureHalted (#318)
//    inside build_liquidation_plan's SeizureLeg loop over seized_collaterals.
liquidate(liquidator, acc, [(D_key, pay)], SeizeMode::Transfer)  // panics
liquidate(liquidator, acc, [(D_key, pay)], SeizeMode::Credit(0)) // panics

// 5. Account remains unliquidatable while the dust NS position is held;
//    debt accrues and collateral deteriorates → eventual bad debt.
```

Relevant code: `contracts/controller/src/positions/liquidation/plan.rs:81-89` (per-leg `SeizureLeg` enforcement over all pro-rata seized legs), `contracts/controller/src/positions/mod.rs:257-277` (`no_seize` → `SpokeAssetSeizureHalted`), `contracts/controller/src/positions/mod.rs:216-228` (`require_can_supply` ignores `no_seize`), `contracts/controller/src/config/asset.rs:106-124` (independent flag ratchet allowing `no_seize` without `paused`/`frozen`).