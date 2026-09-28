### Title
Attacker can shield an underwater account from liquidation and bad-debt cleanup by planting a cheap collateral leg priced through an Aquarius pool they can drain below `min_pool_value_wad` - (File: contracts/price-aggregator/src/providers/aquarius.rs)

### Summary
The SKR EOS congestion attack let an unprivileged user block competing transactions with spam. The XOXNO Lending analog is a self-inflicted price-feed outage: every account liquidation iterates **all** of the account's collateral legs and reprices each one, and `clean_bad_debt` does the same. Supply requires no price, so any user can add a dust collateral leg of an Aquarius LP token, then — as a liquidity provider in that Aquarius pool — withdraw liquidity until the pool's value falls below the configured `min_pool_value_wad`, making `aquarius::read` return `InsufficientAquariusLiquidity`. Every `liquidate` and `clean_bad_debt` against that account then reverts until the attacker restores liquidity. This is documented behavior in the threat model (DoS.1: "an indebted borrower can add a dust leg of any listed collateral and choose which feed outage shields the account… For an Aquarius LP leg, liquidity providers can cause that outage") and proven by existing audit tests.

### Finding Description
- `contracts/price-aggregator/src/providers/aquarius.rs::read` computes `pool_value_wad` and errors with `OracleError::InsufficientAquariusLiquidity` when it is below `lp.min_pool_value_wad` (lines 118-122). The attacker controls pool value directly by removing their own liquidity — no oracle dishonesty required.
- Supply is not price-gated, so a dust leg of the LP token can be planted cheaply (threat-model DoS.1; `tests/test-harness/tests/controller/audit_supply_stale_shield.rs` shows the equivalent stale-feed variant where `try_supply` succeeds while the leg's feed is broken).
- Liquidation seizes pro-rata across *every* collateral leg, so the whole call reverts if any leg is unpriceable. `tests/test-harness/tests/controller/audit_liquidate_and_clean_stale_leg.rs` demonstrates `liquidate`, `clean_bad_debt`, and even `withdraw` reverting with `PRICE_FEED_STALE` while the twin account liquidates normally — the dust leg alone bricks the account.

### Impact Explanation
Temporary freezing of funds / protocol insolvency. The attacker borrows at max LTV, then holds the shield up during a collateral crash. Liquidators cannot act while the position slides into bad debt, and `clean_bad_debt` reverts too, so losses socialize to suppliers via `apply_bad_debt_to_supply_index` instead of being absorbed by timely seizure. Cost to the attacker is one dust deposit plus their own LP position.

### Likelihood Explanation
Fully reachable by a single unprivileged address: `supply` the LP token (no price needed), `borrow`, then call Aquarius `withdraw_liquidity` until the pool value drops under `min_pool_value_wad`. Reversible at will by re-adding liquidity. Requires the account to hold a controlling share of a listed Aquarius pool (or to ride an organic outage, per the stale-feed test), which bounds likelihood — hence Medium, not High.

### Recommendation
Skip unpriceable collateral legs in the liquidation/cleanup pro-rata plan (seize only priceable legs), or gate `supply`/`top-up` of a new collateral leg on its price resolving, or treat an LP leg's `InsufficientAquariusLiquidity` as zero-value rather than a hard revert. Excluding the leg also removes its contribution to HF, which is conservative.

### Proof of Concept
Mirrors `audit_liquidate_and_clean_stale_leg.rs` with the outage self-inflicted instead of a stale Reflector feed:
1. Attacker supplies real collateral (e.g., USDC), borrows ETH near max LTV.
2. Attacker supplies a dust amount of a listed Aquarius LP token whose pool the attacker dominates as LP.
3. Attacker calls `withdraw_liquidity` on the Aquarius pool until `pool_value_wad < min_pool_value_wad`.
4. Market moves; account goes underwater. `liquidate(liquidator, account_id, payments, SeizeMode::Transfer)` reverts with `InsufficientAquariusLiquidity`; `clean_bad_debt` reverts identically. Twin account without the leg liquidates normally (as in the existing test).
5. Debt grows into bad debt; eventual cleanup writes down the supply index at suppliers' expense.