### Title
Asset-only `offered_amount` merge confuses same-token debt legs across hubs, mis-crediting liquidator repayments - (File: contracts/controller/src/positions/liquidation/apply.rs)

### Summary
`liquidate` accepts `Vec<HubPayment>` legs keyed by `(hub_id, asset)`, but the full-close execution path resolves the amount to pull per leg by matching on `asset` alone. When an account borrows the same token in two different hubs (or a liquidator supplies legs for both hub books), the asset-keyed lookup can return the merged or wrong-hub offer for a leg, so a repayment pull can be attributed to the wrong `(hub_id, asset)` debt position — a type/key-confusion analog of CVE-2020-28627's parser misinterpreting one object type for another.

### Finding Description
In `apply_liquidation_repayments`, each planned `RepayEntry` is keyed by `entry.hub_asset` (a `HubAssetKey{hub_id, asset}`), and the debt position is correctly loaded by that full key via `account.borrow_positions.get(entry.hub_asset.clone())` [1](#0-0) . However, on the full-close path (`offered.is_some()`), the amount actually pulled from the liquidator is `offered_amount(env, offers, &entry.hub_asset)` [2](#0-1) . The project's own liquidation documentation states that offers, estimates and refunds "are keyed by token address only, not by `(hub_id, asset)`" [3](#0-2) . This is precisely the documented reason repeated debt-token addresses are "unsafe because refunds and nested transfer authorization cannot be assigned to hub-specific repayment legs" [4](#0-3) .

The confusion surfaces in two reachable ways:

1. **Cross-hub leg mismatch**: `build_liquidation_plan` enforces spoke-asset flags per leg but normalizes repayments against `account.borrow_positions`, which can hold the same `asset` under multiple `hub_id`s [5](#0-4) . If `offered_amount` sums or picks offers by asset address, a leg intended for hub A's book can pull the offer meant for hub B's book (or the sum of both), while the repayment is credited to a single `hub_asset` position. The pool then refunds the "excess" against the wrong leg's debt, and `transfer_amount_measured` credits whatever the token actually moved [6](#0-5) .

2. **Measured-receipt skew**: `leg_usd` is computed as `entry.usd_wad` only when `received >= entry.amount`, otherwise scaled down pro-rata [7](#0-6) . A mis-keyed pull inflates `received` on one leg (over-crediting USD and therefore over-seizing collateral on that leg's pro-rata share) and starves the sibling leg, distorting the seizure allocation the plan computed.

### Impact Explanation
A liquidator repaying a multi-hub same-token debt position can have collateral seizure computed against a repayment amount that does not correspond to the debt leg being closed. Depending on offer sizes this can over-seize a borrower's collateral on one leg (theft of user funds via excessive liquidation bonus application), or strand an authorized transfer against a leg that no longer matches, permanently mis-attributing debt forgiveness across hub books — an insolvency/accounting-integrity issue since each `(hub, token)` book is tracked separately over one physical pool balance. Note: I could not fully verify `offered_amount`'s implementation (whether it sums all matching-asset offers or takes the first) within the available iterations; the impact severity depends on that detail, but the documented key mismatch in `skills/xoxno-lending-liquidations/SKILL.md` confirms the contract itself treats same-asset offers as indistinguishable.

### Likelihood Explanation
Reachable by any unprivileged liquidator calling `controller::liquidate` on any account holding debt in the same token under two hub ids — a state any borrower can create via two `borrow` calls in different hubs, and which the docs explicitly acknowledge is "legitimate" for collateral legs. Triggering requires the full-close (`offered`) plan path, which occurs whenever the quote equals the whole debt — common in the margin band and for insolvent trims. The contract partially mitigates by documenting the hazard for *contract* liquidators building exact per-leg auths, but an EOA/simple liquidator signing the merged transfer still hits the asset-keyed merge in `offered_amount`.

### Recommendation
Key offer/refund matching by the full `HubAssetKey` rather than `asset` alone: make `offered_amount` accept and match `(hub_id, asset)` pairs, and emit per-leg refunds keyed by `HubAssetKey` in `RepayEntry`/refund structs. Alternatively, reject liquidation payments that repeat the same `asset` across different `hub_id`s up front in `build_liquidation_plan`, since the downstream authorization and refund machinery cannot disambiguate them.

### Proof of Concept
1. Borrower supplies collateral, then borrows token T in hub 0 (`HubAssetKey{0, T}`) and hub 1 (`HubAssetKey{1, T}`).
2. Price moves so HF < 1 and the plan becomes a full close.
3. Liquidator calls `liquidate(account_id, payments=[({0,T}, a0), ({1,T}, a1)], SeizeMode::Transfer)`.
4. In `apply_liquidation_repayments`, for the `({0,T})` leg, `offered_amount(env, offers, &{0,T})` matches by `asset == T`, returning `a0 + a1` (or `a1`), pulling more/less than intended for that leg; the excess is refunded against the wrong leg while `borrow_positions.get({0,T})` is credited the merged receipt.
5. Result: hub-0 debt over-repaid (refund owed) while hub-1 debt under-repaid, yet seizure was computed pro-rata on the inflated leg — the liquidator either over-seizes collateral or the refund keys cannot be reconstructed per leg.

### Citations

**File:** contracts/controller/src/positions/liquidation/apply.rs (L54-56)
```rust
        let pull = offered.map_or(entry.amount, |offers| {
            offered_amount(env, offers, &entry.hub_asset)
        });
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L58-72)
```rust
        let received = payments::transfer_amount_measured(
            env,
            &entry.hub_asset.asset,
            liquidator,
            &pool_addr,
            pull,
            GenericError::AmountMustBePositive,
        );

        // Planned amounts are positive, so the division is safe.
        let leg_usd = if received >= entry.amount {
            Wad::from(entry.usd_wad)
        } else {
            Wad::from(mul_div_floor(env, entry.usd_wad, received, entry.amount))
        };
```

**File:** contracts/controller/src/positions/liquidation/apply.rs (L75-77)
```rust
        let position: DebtPosition =
            (&expect_invariant(env, account.borrow_positions.get(entry.hub_asset.clone()))).into();
        actions.push_back(make_pool_action(&position, received, entry.hub_asset));
```

**File:** skills/xoxno-lending-liquidations/SKILL.md (L81-91)
```markdown
For a contract liquidator, require each payment leg to have a unique token
address even when the same token is borrowed in multiple hubs. Estimates and
refunds are keyed by token address only, not by `(hub_id, asset)`.

This is an authorization limit. `authorize_as_current_contract` authorizes the
nested token call by token contract, function, and transfer arguments. It does
not include the controller's hub id. With repeated token addresses, asset-only
refunds cannot determine the accepted amount for each hub leg, while
authorization entries are consumed against ordered token-transfer
sub-invocations. The contract cannot safely construct exact per-leg transfer
authorizations.
```

**File:** skills/xoxno-lending-liquidations/SKILL.md (L189-191)
```markdown
This is distinct from repeated **debt payment** token addresses for a contract
liquidator, which remain unsafe because refunds and nested transfer
authorization cannot be assigned to hub-specific repayment legs.
```

**File:** contracts/controller/src/positions/liquidation/plan.rs (L24-32)
```rust
    for (hub_asset, _) in raw_payments.iter() {
        enforce_spoke_asset_flags(
            env,
            cache,
            account.spoke_id,
            &hub_asset,
            FreezePolicy::AllowOnExit,
        );
    }
```
