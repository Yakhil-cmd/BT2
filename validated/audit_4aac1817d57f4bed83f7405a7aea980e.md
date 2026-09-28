### Title
Sustained high-utilization whale market overflows `i128` inside accrual and permanently freezes the market — ([File: contracts/pool/src/cache/scale.rs](contracts/pool/src/cache/scale.rs))

### Summary
Analog of CVE-2023-21883 (optimizer hang/crash → repeatable complete DOS): every state-changing verb on a pool market first runs `global_sync` accrual, which calls `calculate_utilization` → `scaled_to_original(borrowed, borrow_index)`. When a market carries enough scaled debt/supply shares and the borrow index has compounded high enough, the RAY-valued product exceeds `i128` and panics with `MATH_OVERFLOW`. Because accrual runs before repay, withdraw, liquidate, and `update_indexes`, the panic is permanent: the market can never be touched again and all supplier funds in it are frozen forever.

### Finding Description
- `contracts/pool/src/interest.rs:20-33` — `global_sync` unconditionally accrues before any op via `cache.needs_accrual()`.
- `contracts/pool/src/cache/scale.rs:19-27` — `calculate_utilization` computes `scaled_to_original(self.borrowed, self.borrow_index)` and `scaled_to_original(self.supplied, self.supply_index)`; this multiplication is what overflows.
- The protocol's own stress test proves the cliff is reachable before the `MAX_BORROW_INDEX_RAY` cap engages: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` in `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-360` shows that after enough years at ~98% utilization on an 18-decimal market, `try_update_indexes_for` fails with `MATH_OVERFLOW`, and subsequently both `withdraw` and `repay` revert with the same error — "The market is frozen: exits and repayments accrue first and hit the same panic."

The reachable path for an unprivileged attacker: `supply` a very large position into a high-decimal market, `borrow` to push utilization near `max_utilization`, then let time accrue (or keep the position alive while natural borrowing keeps utilization pinned high). Once `borrowed_scaled * borrow_index > i128::MAX`, no verb on that market ever succeeds again.

### Impact Explanation
Permanent freezing of funds. Every supplier's deposit in the affected market is locked: `withdraw`, `repay`, `liquidate`, `clean_bad_debt`, and even `update_indexes` all accrue first and hit the same `MATH_OVERFLOW` panic. This is a complete, unrecoverable DOS of the market — the exact analog of the MySQL crash/hang class, mapped onto the protocol's "accrue-before-everything" shape. Unlike a transient revert, there is no recovery path since the overflow lives in the accrual step itself.

### Likelihood Explanation
Medium, mirroring the CVE's 4.9. Requirements are steep but entirely within unprivileged reach: a market on a high-decimal (18) asset with a steep rate curve, supply on the order of a billion whole tokens (feasible for low-unit-price assets), utilization sustained near the cap so the borrow index compounds ~170× before the `MAX_BORROW_INDEX_RAY` clamp can engage. No admin action, leaked key, or external dependency is needed — only `supply` and `borrow` plus time. An attacker with large capital could deliberately create the conditions; a dormant high-utilization market could also drift into it naturally.

### Recommendation
- Bound the value multiplication: compute utilization in a wider type (e.g., `U256`) or compare `borrowed`/`supplied` scaled shares against `i128::MAX / index` before multiplying, and saturate/clamp rather than panic.
- Enforce the index cap before the value ceiling: when `borrow_index` approaches `MAX_BORROW_INDEX_RAY`, clamp accrual so the index stops growing while `scaled * index` stays under `i128::MAX` — the cap currently engages too late because the ray-value overflow fires first.
- Add a supply-side ceiling per market (`max_cap_for_decimals` style cap tightened so `scaled * MAX_BORROW_INDEX_RAY < i128::MAX`) so the overflow domain is unreachable regardless of utilization history.
- Regression: keep `large_positions_and_long_horizons.rs` asserting the cliff, but change the expectation to a graceful cap/clamp instead of `MATH_OVERFLOW`.

### Proof of Concept
See `tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-360`: an 18-decimal market seeded with `1e9 * 1e18` supply, a 98%-of-principal borrow, `max_utilization` disabled, and time advanced yearly. `try_update_indexes_for(&["BIG18"])` eventually returns `MATH_OVERFLOW` while `borrow_index < MAX_BORROW_INDEX_RAY`, after which `try_withdraw_raw(BOB, "BIG18", 1)` and `try_repay(ALICE, "BIG18", 1.0)` both fail with `MATH_OVERFLOW` — the market is permanently frozen.