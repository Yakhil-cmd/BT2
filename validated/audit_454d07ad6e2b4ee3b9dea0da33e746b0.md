### Title
Dust collateral leg priced through a drainable Aquarius LP source permanently bricks liquidation and bad-debt cleanup for the account - (File: contracts/controller/src/risk/totals.rs)

### Summary
CVE-2020-2760 is a repeatable-crash/DoS class: an attacker induces a condition under which the victim operation always aborts. The XOXNO Lending analog is account-scoped liquidation DoS: `calculate_account_risk_totals` loads a strict price for every supply leg on the account, so a single collateral asset whose price feed fails makes every `liquidate` call (and `clean_bad_debt`, which requires "valid required prices") revert for that account. Because `supply` requires no price read for the account's other assets to be valued, an indebted borrower can add a dust supply leg of any listed collateral — in particular an Aquarius LP token — and any third party (or the borrower's own LP position) can then drain that pool below `min_pool_value_wad`, making the LP price permanently return `InsufficientAquariusLiquidity`. The account becomes unliquidatable and un-cleanable until pool liquidity recovers, which may be never.

### Finding Description
`calculate_account_risk_totals_body` iterates every supply position and calls `cache.cached_price(&hub_asset.asset)` unconditionally (`contracts/controller/src/risk/totals.rs:171-186`). It is invoked inside `build_liquidation_plan` (`contracts/controller/src/positions/liquidation/plan.rs:34-44`), so a failed strict price read on any single collateral leg aborts the whole liquidation before repayment or seizure planning. The same totals are required by `clean_bad_debt` ("valid required prices", `docs/reference/invariants.md` INV-LIQ-04), and even the owner-gated `force_socialize_bad_debt` reads the account's prices.

On the oracle side, the Aquarius LP provider computes `pool_value_wad = price_wad * total_shares / share_unit` and returns `Err(OracleError::InsufficientAquariusLiquidity)` whenever the pool value is below the configured `lp.min_pool_value_wad` (`contracts/price-aggregator/src/providers/aquarius.rs:118-122`). Aquarius pools are permissionless AMMs: liquidity providers can withdraw at will, driving total pool value under the threshold, which flips the LP token's price to unusable.

Attack path (single unprivileged address, or borrower + LP colluding):

1. Borrower opens an account, supplies normal collateral (e.g. USDC) and borrows to near the limit.
2. Borrower calls `supply` to add a dust leg of a listed Aquarius LP collateral asset. Supply of a new listed asset does not require the borrower's whole book to be priced below the gate's HF check path in a way that blocks the deposit — the threat model documents "Supply needs no price, so an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account" (`docs/explanation/threat-model.md` DoS.1).
3. Attacker (or the same user, if they are an LP) withdraws liquidity from the referenced Aquarius pool until `price_wad * total_shares < min_pool_value_wad`.
4. The LP asset's price read now fails. Every subsequent `liquidate`, `clean_bad_debt`, and `force_socialize_bad_debt` on that account reverts in `calculate_account_risk_totals` before any leg is processed.
5. The borrower lets interest accrue; the position goes deeply underwater while no liquidation can execute. Eventually the debt becomes unbacked bad debt that still cannot be cleaned up because cleanup also needs the failing price.

### Impact Explanation
Protocol insolvency / permanent freezing of the risk-removal path: the account's debt accrues unbounded while collateral cannot be seized and bad debt cannot be socialized, so losses are silently transferred to suppliers of the borrowed markets. The shield costs the borrower only a dust deposit plus pool withdrawal; the blocker persists as long as the pool stays below `min_pool_value_wad`, and the borrower can re-trigger it against multiple accounts. This matches the accepted impact class of temporary/permanent freezing and insolvency rather than a mere fail-closed inconvenience, because the frozen operation is the protocol's solvency enforcement itself.

### Likelihood Explanation
Medium. It requires the spoke to list an Aquarius LP collateral (mainnet configs contain `min_pool_value` entries for exactly such sources) and enough LP liquidity control to cross the configured floor — cheaper for shallow pools or high thresholds, and fully within the attacker's control when the attacker is itself a large LP of that pool. No privileged role, no oracle dishonesty within bands, and no third-party contract misbehavior is needed: the price fails closed on true on-chain state. The scenario is explicitly registered as threat DoS.1 in `docs/explanation/threat-model.md`, indicating the mechanism is known but not mitigated in code.

### Recommendation
Decouple a failing collateral price from total liquidation blocking:

- In `build_liquidation_plan`/`calculate_account_risk_totals` for liquidation and cleanup paths, treat a supply leg whose price is unusable as zero-valued collateral (drop the leg from pro-rata seizure, or revert only if *all* legs are unpriceable), so one bad feed cannot shield the whole account; or
- Add a liquidation variant that seizes only the priceable legs and writes down the unpriceable leg as bad debt; and
- Ensure `clean_bad_debt`/`force_socialize_bad_debt` can proceed while zeroing unpriceable collateral, so insolvency can be socialized even during a feed outage.
- At listing time, bound `min_pool_value_wad` high enough relative to realistic LP exit capacity that draining below it is uneconomic.

### Proof of Concept
1. Governance lists `AQUA-LP` (Aquarius LP token) as collateral in spoke S with oracle `AquariusLpSource { pool: P, min_pool_value_wad: 50_000 WAD }`.
2. Alice supplies 10,000 USDC, borrows 7,000 XLM-equivalent debt.
3. Alice calls `supply(alice, account_id, (hub, AQUA-LP), dust_amount)` — accepted; the leg is now in `account.supply_positions`.
4. Alice (an LP of pool P) calls P's `withdraw` until `reserve`-derived `pool_value_wad < 50_000 WAD`. `providers::aquarius::read` now returns `InsufficientAquariusLiquidity` (`aquarius.rs:118-122`), so the aggregator reports the asset unusable and `cache.cached_price` panics inside `calculate_account_risk_totals_body` (`totals.rs:171-186`).
5. XLM price moves / interest accrues so Alice's HF < 1. Liquidator calls `liquidate(liquidator, alice_id, [(hub, XLM, full_debt)], SeizeMode::Transfer)` — reverts in `build_liquidation_plan → calculate_account_risk_totals` before any seizure (`plan.rs:34-44`).
6. `clean_bad_debt(alice_id)` reverts identically (INV-LIQ-04 requires "valid required prices"). The account is permanently shielded; debt accrues until collateral is exhausted and suppliers of the XLM market absorb the loss via a later index write-down that can still not be executed while the feed is down.