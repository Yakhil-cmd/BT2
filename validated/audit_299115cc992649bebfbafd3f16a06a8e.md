### Title
Borrower can supply a `no_seize`-flagged asset to permanently brick liquidation of their account - (File: contracts/controller/src/positions/mod.rs)

### Summary
Liquidation seizure is pro-rata across every supply leg of the account, and each leg is gated by `FreezePolicy::SeizureLeg`, which reverts with `SpokeAssetSeizureHalted` when the listing's `no_seize` flag is set. However, the entry gate for `supply` (`FreezePolicy::BlockOnEntry`) only rejects `paused` and `frozen` — it does not check `no_seize`. A borrower can therefore supply a `no_seize`-flagged collateral asset into an account that already carries debt, after which every liquidation attempt reverts, mirroring the Teller `commitCollateral` zero-amount griefing vector.

### Finding Description
In the Teller report, a borrower modifies collateral bookkeeping after the loan starts so that the withdraw path reverts on `"Withdraw amount cannot be zero"`, blocking both liquidation and lender collateral recovery. The XOXNO Lending analogue is a post-borrow position mutation that injects an unseizable leg:

- `supply` → `require_can_supply` → `require_listed_unhalted_config` calls `enforce_spoke_asset_flags` with `FreezePolicy::BlockOnEntry`, which asserts only `!sa.paused` and `!sa.frozen` (`contracts/controller/src/positions/mod.rs:266-269`, invoked at line 196 and 222). `no_seize` is not checked on entry.
- During liquidation, each planned seizure leg is checked with `FreezePolicy::SeizureLeg`, which asserts `!sa.no_seize` and otherwise reverts with `SpokeAssetSeizureHalted` (error #318) (`contracts/controller/src/positions/mod.rs:273-275`). Because seizure is forced pro-rata across all collateral legs, one `no_seize` leg bricks the entire liquidation (`skills/xoxno-lending-liquidations/SKILL.md:61`, `docs/reference/invariants.md:502-504`: "Nonzero no_seize collateral can block the whole proportional liquidation, even if supplied after the flag is set").
- The flag ratchet `require_flag_ratchet` permits governance to set `no_seize` alone (`contracts/controller/src/config/asset.rs:182-186`), so a listed, supply-enabled, non-paused asset with `no_seize = true` is a reachable config state.

Attack path (all unprivileged):

1. Borrower supplies collateral A, borrows asset B.
2. Governance sets `no_seize` on listed collateral asset C (without `paused`/`frozen`), e.g. during a seizure-risk emergency on that token.
3. Borrower calls `supply` adding a nonzero amount of C to their account — accepted, since entry does not check `no_seize`.
4. Price/accrual pushes the account below HF = 1.
5. Every `liquidate` call reverts with `SpokeAssetSeizureHalted`, because the pro-rata plan includes a C leg and `SeizureLeg` rejects it.
6. `clean_bad_debt` cannot recover either: permissionless cleanup requires total collateral ≤ $5 dust, which fails for a solvent-collateral account, so lender funds stay frozen until governance executes `relax_spoke_asset_flags`.

### Impact Explanation
Lenders cannot recover the debt position through liquidation while the `no_seize` leg exists, and the dust-capped `clean_bad_debt` path is unavailable for accounts holding meaningful collateral. This is temporary freezing of lender funds (liquidation DoS) plus forced reliance on a governance timelock (`relax_spoke_asset_flags`, epoch-checked in `asset.rs:129-146`) to restore liquidatability. The borrower additionally gains time to repay or ride a price recovery, matching the original report's impact.

### Likelihood Explanation
Requires a `no_seize`-only flag state on a listed asset, which the ratchet and runbooks (`docs/reference/runbooks/freeze-a-listing.md`) explicitly support as an emergency tool. Once such a flag exists, the exploit costs the borrower only one `supply` call of a nonzero amount — no privileged access. Severity: Medium — contingent on a governance flag state, impact is temporary freeze rather than permanent loss.

### Recommendation
Include `no_seize` in the entry rejection set: in `FreezePolicy::BlockOnEntry` (`contracts/controller/src/positions/mod.rs:266-269`), also assert `!sa.no_seize` with `SpokeError::SpokeAssetSeizureHalted` (or a dedicated error), so new unseizable collateral cannot be supplied while the flag is set. Alternatively, drop `no_seize` legs from the proportional seizure plan instead of reverting the whole liquidation.

### Proof of Concept
```rust
// Precondition: market C is listed, is_collateralizable = true,
// paused = false, frozen = false, no_seize = true (set via
// set_spoke_asset_flags, which the ratchet permits standalone).

// 1. Borrower opens a normal position.
t.supply(ALICE, "USDC", 10_000.0);
t.borrow(ALICE, "ETH", 5.0);

// 2. Governance sets no_seize on asset C (asset stays unpaused/unfrozen).
//    t.set_spoke_asset_flags(C, paused=false, frozen=false, no_seize=true);

// 3. Borrower adds a nonzero leg of C — entry only checks paused/frozen.
t.supply(ALICE, "C", 1.0); // succeeds under FreezePolicy::BlockOnEntry

// 4. Account becomes unhealthy.
t.set_price("USDC", usd_cents(10));
t.assert_liquidatable(ALICE);

// 5. Every liquidation reverts: the pro-rata plan includes the C leg,
//    and FreezePolicy::SeizureLeg asserts !no_seize.
let err = t.try_liquidate(LIQUIDATOR, ALICE, "ETH", 1.0);
assert_contract_error(err, errors::SPOKE_ASSET_SEIZURE_HALTED); // #318

// 6. clean_bad_debt is unavailable: collateral >> $5 dust threshold.
//    Lender funds remain frozen until relax_spoke_asset_flags executes.
```

Note: the behavior is partially acknowledged in `docs/reference/invariants.md` (INV-HALT-02), so this may be treated as a documented design trade-off rather than a defect; the entry-side gap (supplying *new* unseizable collateral after the flag is set) is the specific weakness worth flagging.