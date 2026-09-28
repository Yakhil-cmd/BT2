### Title
Unprivileged liquidation/cleanup DoS via a dust supply leg on a stale-priced asset - (File: contracts/controller/src/positions/supply.rs)

### Summary
A borrower can plant a dust-sized supply position in an asset whose oracle price feed is stale (or which later goes stale) without any freshness check on the supply path. Because liquidation, `clean_bad_debt`, and even the borrower's own `withdraw` resolve strict, fresh prices for **every** position on the account's book, that one worthless leg makes every liquidation and bad-debt cleanup revert with `PriceFeedStale` for as long as the feed stays stale. This mirrors the CVE class: unauthenticated input supplied to a component (JSSE/TLS → strict price reads over all account positions) degrades the system into a denial of service.

### Finding Description
`supply` accepts a new position leg without requiring that asset's oracle price to be fresh — the in-repo test asserts this explicitly: `try_supply(borrower, "WBTC", 0.001)` succeeds after the WBTC Reflector price is backdated by 3,600 seconds, and the "poisoned" leg persists with non-zero scaled shares. [1](#0-0) 

Downstream, the risk engine prices **all** supply and debt positions of the account with strict (freshness-checked) prices inside the shared `Context` cache ("Required lending valuations use strict prices and cache results within the operation context"). [2](#0-1)  Consequently, once the account is underwater:

- `liquidate` reverts `PRICE_FEED_STALE` regardless of `debt_payments` or `SeizeMode` — the stale leg is part of the pro-rata collateral set and of the HF computation. [3](#0-2) 
- Permissionless `clean_bad_debt` reverts `PRICE_FEED_STALE` too (cleanup "requires ... valid required prices" per INV-LIQ-04). [4](#0-3) [5](#0-4) 
- Even the borrower's own `withdraw` on an unrelated asset reverts `PRICE_FEED_STALE`, because withdrawal also computes post-op health over the whole book. [6](#0-5) 

The attacker needs only one unprivileged `supply` call of e.g. 0.001 units timed to a stale feed window — or simply a feed that goes stale after the leg exists.

### Impact Explanation
While the planted leg's feed is stale, the account is completely unliquidatable and its bad debt cannot be permissionlessly cleaned. Interest keeps accruing on the debt ("Interest continues while a listing is paused... Missing prices ... remain independent obstacles"). [7](#0-6)  If collateral value keeps falling during the outage, the account crosses from under-collateralized into insolvent, and the eventual cleanup writes the loss down against supplier indexes — protocol insolvency / temporary freezing of lender funds, both in the accepted impact set. The dust leg costs the attacker almost nothing and can sit on a book until needed; recovery requires the upstream feed to resume, which the protocol cannot force.

### Likelihood Explanation
Medium. The path is a single permissionless `supply` call and the repo ships two dedicated reproductions (`audit_supply_stale_shield`, `audit_liquidate_and_clean_bricked_by_unpriceable_dust_leg`), showing the maintainers treat the mechanism as real. The constraint is the trigger: it needs an oracle feed outage/staleness window on a listed asset, which is an external condition. Deliberate self-shielding requires timing a listing to a stale window or opportunistically holding dust legs; accidental occurrences (feed downtime after a dust supply) happen without any attacker. Because the DoS is temporary and conditional on oracle downtime rather than permanently attacker-controlled, it maps to Medium, matching the source advisory's partial-DoS severity.

### Recommendation
Gate supply-side position creation on a fresh, valid price for the supplied asset (reuse the same strict-price path the risk engine uses), so a leg that would later brick account-level risk reads cannot be created while unpriceable. Additionally or alternatively, consider excluding legs whose strict price is unavailable *and* whose scaled value is below the dust threshold from the required-price set in liquidation/cleanup, so a worthless leg cannot hold the whole account hostage. Note the current tests pin the permissive behavior (`"supply must accept the leg even though WBTC's feed is stale"`), so fixing this requires intentionally flipping those assertions.

### Proof of Concept
Executable reproduction already in-repo: `tests/test-harness/tests/controller/audit_supply_stale_shield.rs` and `audit_liquidate_and_clean_stale_leg.rs`. Sequence:

1. `supply(BOB/ALICE, USDC, 10_000)`, `borrow(ALICE, ETH, 3.0)` — healthy account.
2. Backdate the WBTC Reflector price by 3,600 s (stale feed): `mock_reflector_client().set_price_at(wbtc, usd(60_000), now - 3_600)`.
3. `supply(ALICE, WBTC, 0.001)` — **succeeds**, planting a near-worthless leg with an unpriceable valuation.
4. Crash USDC to $0.50 → `is_liquidatable(ALICE)` true on the real collateral.
5. `liquidate(LIQUIDATOR, ALICE, ETH, 1.0)` → `PriceFeedStale` (reverts).
6. `clean_bad_debt(account_id)` → `PriceFeedStale` (reverts).
7. `withdraw(ALICE, WBTC, dust)` → `PriceFeedStale` (reverts).
8. Refresh WBTC price → identical liquidation succeeds, confirming the stale leg — not the account state — is the blocker. [8](#0-7)

### Citations

**File:** tests/test-harness/tests/controller/audit_supply_stale_shield.rs (L17-69)
```rust
    let pre = t.try_liquidate(LIQUIDATOR, ALICE, "ETH", 1.0);
    test_harness::assert_contract_error(pre, errors::HEALTH_FACTOR_TOO_HIGH);

    t.advance_time(5_000);
    let now = t.env.ledger().timestamp();
    let wbtc = t.resolve_asset("WBTC");
    t.mock_reflector_client()
        .set_price_at(&wbtc, &usd(60_000), &(now - 3_600));

    let plant = t.try_supply(ALICE, "WBTC", 0.001);
    assert!(
        plant.is_ok(),
        "supply must accept the leg even though WBTC's feed is stale: {plant:?}"
    );
    t.assert_position_exists(ALICE, "WBTC", PositionType::Supply);
    assert!(
        t.supply_balance_raw(ALICE, "WBTC") > 0,
        "poisoned WBTC leg must persist with a non-zero scaled share"
    );

    t.set_price("USDC", usd_cents(50));

    assert!(
        t.can_be_liquidated(BOB),
        "twin account must be underwater so the crash — not the leg — drives HF<1"
    );
    t.liquidate(LIQUIDATOR, BOB, "ETH", 1.0);
    assert!(
        t.borrow_balance(BOB, "ETH") < 3.0,
        "twin liquidation must succeed with fresh feeds"
    );

    let alice_id = t.resolve_account_id(ALICE);

    let liq = t.try_liquidate(LIQUIDATOR, ALICE, "ETH", 1.0);
    test_harness::assert_contract_error(liq, errors::PRICE_FEED_STALE);

    let clean = t.try_clean_bad_debt_by_id(alice_id);
    test_harness::assert_contract_error(clean, errors::PRICE_FEED_STALE);

    let wd = t.try_withdraw(ALICE, "WBTC", 0.0001);
    test_harness::assert_contract_error(wd, errors::PRICE_FEED_STALE);

    t.set_price("WBTC", usd(60_000));
    let recovered = t.try_liquidate(LIQUIDATOR, ALICE, "ETH", 1.0);
    assert!(
        recovered.is_ok(),
        "once WBTC is fresh again, the identical liquidation must succeed: {recovered:?}"
    );
    assert!(
        t.borrow_balance(ALICE, "ETH") < 3.0,
        "post-recovery liquidation must reduce ALICE's debt"
    );
```

**File:** docs/explanation/threat-model.md (L262-266)
```markdown
Price failure can stop liquidation as well as borrowing and withdrawal.
`quotes` can return a nonzero candidate price with `valid=false`; consumers
must honor validity rather than use the price field alone. Required lending
valuations use strict prices and cache results within the operation context,
not a guarantee of identical timestamps across upstream observations.
```

**File:** docs/explanation/threat-model.md (L270-275)
```markdown
Global pause leaves designated exit/recovery endpoints callable. Listing-level
paused debt blocks a repayment leg that selects it. Seizure uses its own
no_seize flag across nonzero planned collateral legs; one such flag can abort
a pro-rata liquidation. It does not prevent new supply by itself. Interest
continues while a listing is paused. Missing prices and liquidity limits remain
independent obstacles even when an entrypoint is not pause-gated.
```

**File:** tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs (L36-37)
```rust
    let liq = t.try_liquidate(LIQUIDATOR, borrower, "ETH", 1.0);
    test_harness::assert_contract_error(liq, errors::PRICE_FEED_STALE);
```

**File:** tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs (L39-40)
```rust
    let clean = t.try_clean_bad_debt_by_id(borrower_id);
    test_harness::assert_contract_error(clean, errors::PRICE_FEED_STALE);
```

**File:** docs/reference/invariants.md (L465-469)
```markdown
Permissionless cleanup requires ceil risk debt greater than half-up unweighted
collateral and collateral at or below the fixed $5 dust threshold. Owner-only
forced cleanup omits the dust cap. Both require debt, readable account and NFT
state, valid required prices and no active flash guard. Listing flags and
global pause do not block standalone cleanup.
```
