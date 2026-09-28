### Title
Dust Aquarius-LP collateral leg plus self-induced LP fair-value outage blocks liquidation and bad-debt cleanup - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
The Aquarius LP price provider fails closed with `OracleError::InsufficientAquariusLiquidity` whenever the pool's fair value falls below the configured `min_pool_value_wad`. Because `supply` requires no price read, an indebted borrower can add a dust-sized Aquarius LP share as an extra collateral leg at any time. That same borrower — acting as an LP in the underlying pool — can then withdraw liquidity until the pool value drops below `min_pool_value_wad`, permanently breaking the price for that leg. Any operation that prices the whole account (liquidation health-factor computation, withdrawal from an indebted account, bad-debt cleanup, force-socialization) then reverts, shielding the account while interest accrues.

### Finding Description
In `contracts/price-aggregator/src/providers/aquarius.rs`, `read` computes the LP share's fair price and rejects it when `pool_value_wad < lp.min_pool_value_wad` with `OracleError::InsufficientAquariusLiquidity`. The pool value is derived from live on-chain reserves (`aquarius_pool_reserves_call`) and total shares, so it is attacker-influenceable: a liquidity provider in that pool can withdraw until the threshold is crossed.

On the controller side, the threat model and invariants establish the dependency chain:
- Supply needs no price, so a borrower can add a dust leg of any listed collateral — including the Aquarius LP share — even while already indebted (`docs/explanation/threat-model.md`, DoS.1).
- Health factor, liquidation planning, and withdrawal from an indebted account use strict prices over all of the account's collateral legs; one unusable leg fails the whole valuation. The Liqvid runbook confirms "a lower NAV then fails closed... Borrow and liquidation stop" and that withdrawal from an account with debt also needs the price (`docs/reference/runbooks/liqvid-listing-params.md`, sections 2–3).
- The same failing leg blocks `clean_bad_debt` and the governed force-socialization path (DoS.1), so the account cannot be resolved even once deeply insolvent.

Root cause: an attacker-controllable availability signal (Aquarius pool value vs. `min_pool_value_wad`) is wired into a fail-closed price that gates all account-wide valuation, and account collateral composition is borrower-controlled through permissionless, price-free supply.

### Impact Explanation
Temporary freezing of funds plus protocol insolvency growth. While the feed is broken: (1) no liquidator can liquidate the account regardless of how far below HF 1 it drifts, so debt and interest keep accruing uncollateralized; (2) bad-debt cleanup and force-socialization revert on the same leg, so the bad debt cannot be written down or socialized; (3) any other account holding the same LP collateral cannot withdraw-while-indebted, borrow, or be liquidated (the latter is beneficial for attackers, harmful for the protocol's solvency). The attacker can restore the price at will by re-adding liquidity, making this a controllable, reversible freeze of every account holding that collateral asset — with insolvency accumulating during the outage.

### Likelihood Explanation
Reachable by a single unprivileged address: the attacker supplies the LP token (or acquires dust of it), opens a borrow, supplies a dust LP collateral leg via `supply`, then calls `withdraw` on the Aquarius pool to push pool value under `min_pool_value_wad`. Requires the attacker to hold LP share position in the listed pool — cheap for small/shallow pools, which are exactly the pools a low `min_pool_value_wad` is meant to guard. The trigger is a "configuration/option"-dependent availability knob (the `min_pool_value_wad` threshold in the oracle source config), matching the MySQL "Options"-related availability bug class of CVE-2016-0661: a normal user input path (LP withdrawal, permissionless supply) reaching an availability failure through a configured boundary. Medium severity: conditional cost, attacker-controlled reversibility, impact bounded to accounts/markets using that collateral.

### Recommendation
- Price collateral legs independently during liquidation and bad-debt cleanup: treat an unpriceable leg as zero-valued collateral rather than aborting the entire valuation, so the remaining priced collateral can still be seized against the debt.
- Alternatively, allow `clean_bad_debt` and liquidation plans to drop/skip unpriceable dust legs (below the dust threshold) instead of failing closed on them.
- Add a minimum-time-below-threshold or hysteresis on `min_pool_value_wad` (e.g., require the pool value to remain below the floor for N ledgers, enforced via a stored observation) so a single-transaction LP withdrawal cannot toggle feed availability.
- Consider requiring a price read (or forbidding collateral-enable) when a borrower adds a new collateral asset to an already-indebted account.

### Proof of Concept
1. Governance lists an Aquarius LP share `LPS` as collateral in spoke `S`, priced via `AssetOracle::AquariusLp(lp)` with `min_pool_value_wad = V`.
2. Attacker (LP provider in `lp.pool`):
   a. `supply(LPS, dust)` — succeeds, no price needed; account gains collateral leg `LPS`.
   b. `borrow(X, amount)` against the LP leg plus other collateral.
   c. Call `lp.pool.withdraw(...)` to pull liquidity until `price_wad * total_shares / share_unit < V`.
3. Any `liquidate(account, ...)` call now reverts inside `aquarius::read` at the `pool_value_wad < lp.min_pool_value_wad` check (`InsufficientAquariusLiquidity`), because the Context's strict price for `LPS` fails, and the account's HF cannot be computed.
4. `clean_bad_debt(account)` reverts identically even after the account is deeply insolvent; force-socialization is blocked the same way.
5. Attacker restores the price by re-depositing liquidity into the pool, unwinding or repositioning, and can repeat — each outage window accrues uncollateralized interest that the protocol cannot resolve while the leg is unpriceable.

Relevant code: `aquarius::read` fair-value/liquidity gate — [1](#0-0) ; live reserve reads that make the gate attacker-influenceable — [2](#0-1) ; documented reachable chain (price-free supply, dust leg shields liquidation and cleanup) — [3](#0-2) ; fail-closed pricing stops borrow/liquidation and indebted withdrawal — [4](#0-3) .

### Citations

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L88-94)
```rust
    let price_a = engine::resolve_nested(session, &lp.key_a, depth + 1)?;
    let price_b = engine::resolve_nested(session, &lp.key_b, depth + 1)?;
    let (reserve_a, reserve_b) =
        aquarius_pool_reserves_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
    let total_shares =
        aquarius_total_shares_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;

```

**File:** contracts/price-aggregator/src/providers/aquarius.rs (L109-122)
```rust
    let price_wad = if stable {
        let amp = aquarius_amp_call(&env, &lp.pool).ok_or(OracleError::NoLastPrice)?;
        fair_stable_lp_price_wad(&env, &leg_a, &leg_b, &supply, amp)?
    } else {
        fair_lp_price_wad(&env, &leg_a, &leg_b, &supply)?
    };
    let share_unit = 10i128
        .checked_pow(share_decimals)
        .ok_or(OracleError::InvalidPrice)?;
    let pool_value_wad = try_mul_div_half_up(&env, price_wad, total_shares, share_unit)
        .ok_or(OracleError::InvalidPrice)?;
    if pool_value_wad < lp.min_pool_value_wad {
        return Err(OracleError::InsufficientAquariusLiquidity);
    }
```

**File:** docs/explanation/threat-model.md (L364-365)
```markdown
| DoS.1 | Price outage blocks valuation-dependent actions, including liquidation; fail-closed availability cost. Supply needs no price, so an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account. For an Aquarius LP leg, liquidity providers can cause that outage by withdrawing pool value below `min_pool_value_wad`. The same leg blocks bad-debt cleanup and force-socialization. |
| DoS.2 | Selected paused debt or no_seize collateral blocks liquidation; distinct flag policies matter. |
```

**File:** docs/reference/runbooks/liqvid-listing-params.md (L117-121)
```markdown
Every price below the floor or above the ceiling fails closed with
`SanityBoundViolated`. Borrow and liquidation stop. A withdrawal from an
account with debt also needs the price. Supply does not need the price,
except when it runs the refresh gate of section 10.

```
