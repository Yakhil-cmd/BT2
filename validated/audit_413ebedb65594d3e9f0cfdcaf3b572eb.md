The strongest analog candidate is the `SUPPLY_INDEX_FLOOR_RAW` clamp leaving unbacked supply claims after a full bad-debt wipeout. Let me verify reachability and whether it's a documented design choice.### Title
Wiped-out suppliers retain a floor-clamped claim that drains the next depositor's cash on a first-come withdrawal - (File: contracts/pool/src/interest.rs)

### Summary
When bad debt is socialized, `apply_bad_debt_to_supply_index` scales the supply index down but clamps it at `SUPPLY_INDEX_FLOOR_RAW` (`RAY/1000`) instead of zero. Supplier shares are never burned, so after a full wipeout every wiped supplier still holds a positive withdrawable claim (`shares × floor`) backed by nothing. Withdrawals only check `require_reserves` (cash covers the transfer), not market backing, so a wiped supplier who front-runs the next deposit can withdraw real tokens belonging to the fresh depositor — the same "overstated total, first claimer wins" shape as the OpenQ finding.

### Finding Description
`interest::apply_bad_debt_to_supply_index` computes `new_supply_index = supply_index * (total_supplied_value - bad_debt) / total_supplied_value` and then takes `max(new_supply_index, SUPPLY_INDEX_FLOOR_RAW)`. When `bad_debt >= total_supplied_value` (a full loss), the proportional result is `0` but the clamp raises the index to `RAY/1000`, while `cache.supplied` shares are untouched — `seize::apply` only calls `burn_debt` on the borrow side.

The resulting phantom claim is `unscale_supply_floor(shares)` ≈ 0.1% of pre-wipeout supply value, unbounded by any dust threshold: a market with $10M wiped supply leaves ~$10k of unbacked claim, spread across all former suppliers.

`withdraw::accounting` → `gate_and_debit` enforces only `cache.require_reserves(net_transfer)` (cash ≥ transfer) plus utilization and supply-for-debt checks; `require_backed_market` / `backing_shortfall` is never invoked on the withdraw path. So the instant any cash is present — e.g., a new depositor calls `supply` — a wiped supplier's `withdraw` resolves their shares at the floor index and transfers real tokens out.

Permissionless reachability: any account can be pushed into a full socialization via `clean_bad_debt` (permissionless, collateral ≤ $5 dust, `D > C`) or via `seize` on the borrow side during liquidation, which calls `apply_bad_debt_to_supply_index` directly. The attacker only needs to have held supply shares before the wipeout and then call `withdraw` after fresh cash arrives.

### Impact Explanation
Theft of user funds. The pool's accounting overstates withdrawable claims: `supplied × supply_index` includes a floor-clamped residual with zero backing, yet the withdraw guard treats any cash in the book as payable. The stranded claim converts into a real token transfer that pays out the next depositor's principal. The harness test `test_raw_cache_floor_clamp_strands_claim_without_supply_guard` asserts exactly this: a stranded wiped position pays out `gross > 0` real tokens and `gross == fresh_cash`, leaving pool cash unable to cover the fresh supplier's claim. First-come ordering decides who loses — identical to the OpenQ prize-pool race.

### Likelihood Explanation
Requires a bad-debt event large enough to fully wipe a market's supply index (or nearly so), which is a tail-risk condition, but `clean_bad_debt` and liquidation seizes are permissionless and the write-down is applied unconditionally whenever residual eligible debt exists. Once the index is clamped at the floor, any wiped supplier can execute the drain the moment new liquidity enters; `recapitalize` exists but does not burn the phantom shares or restore the index, so the window persists until the claims are withdrawn. No privileged access, timing privilege beyond a single transaction ordering, or oracle manipulation is needed.

### Recommendation
When the proportional write-down would push the supply index to (or below) the floor, burn the outstanding supply shares or zero the claimable value instead of leaving `supplied` shares valued at `SUPPLY_INDEX_FLOOR_RAW`. Alternatively, gate withdrawals on `backing_shortfall == 0` for unbacked residual claims, or cap the floor-clamped claim to actual remaining cash so a wiped supplier can never draw funds deposited after the wipeout.

### Proof of Concept
Conceptual sequence, matching the assertions in `contracts/pool/tests/interest.rs::test_raw_cache_floor_clamp_strands_claim_without_supply_guard`:

1. Alice supplies `S` units of hub asset `A`; her position is `S_scaled` shares at `supply_index ≈ RAY`.
2. An insolvent account accrues debt ≥ total supplied value of `A`. Anyone calls `controller.clean_bad_debt(account_id)` (or a liquidation seize hits the borrow side); `seize::apply` → `apply_bad_debt_to_supply_index` sets `supply_index = SUPPLY_INDEX_FLOOR_RAW` and burns the debt shares. Alice's `S_scaled` remains.
3. Bob supplies `D` fresh tokens to `A` (`cash += D`, `supplied += new_shares` at the floored index).
4. Alice front-runs Bob's own exit and calls `withdraw` on `A`. `resolve_withdrawal` pays `unscale_supply_floor(S_scaled) = S_scaled × RAY/1000` — which equals `D` in the worst case — because `require_reserves` sees `cash ≥ gross`. Alice receives tokens she has no economic claim to.
5. Bob's subsequent `withdraw` reverts on `require_reserves` (`InsufficientReserves`): his deposit was drained by a claim that should have been zeroed by the wipeout.

The unit test confirms each step: the floor clamp leaves `stranded > 0`, the stranded withdraw pays `gross == fresh_cash`, and post-conditions show `cache.cash() < fresh_claim` — the fresh supplier's funds are lost.

Uncertain: this floor is described in `contracts/pool/README.md` and the runbook as an "intentional exception" that "can leave a small unbacked claim," so reviewers may classify it as a documented trade-off; however, the residual scales with wiped supply (0.1%), is unbounded relative to dust, and the theft-of-next-deposit consequence demonstrated by the test goes beyond a merely cosmetic residual.