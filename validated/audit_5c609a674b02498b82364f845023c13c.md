### Title
Oversized debt overflows i128 inside accrual, permanently bricking all operations on a market — (File: common/src/rates/index.rs)

### Summary
The analog of CVE-2020-14383 (an authenticated request repeatedly crashes a service shared by many consumers) is a shared-state panic in interest accrual. `calculate_supplier_rewards` multiplies the market's scaled debt by the new borrow index in `i128`; once `borrowed * borrow_index` exceeds `i128::MAX`, accrual panics with `MathOverflow`, and because every market entrypoint runs `global_sync` first, the whole market becomes uncallable — a shared "process" crashed for every user, not just the attacker. The repo's own test suite already demonstrates this freeze (`a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap`, tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:316-361).

### Finding Description
`global_sync` (contracts/pool/src/interest.rs:20-33) is invoked at the top of every mutating market op (`supply`, `borrow`, `withdraw`, `repay`, `net_settle`, `seize_positions`, `recapitalize`, `claim_revenue`). Each chunk calls `accrue_step`, which calls `calculate_supplier_rewards`:

```text
common/src/rates/index.rs:80-81
let old_total_debt = borrowed.mul(env, old_borrow_index);
let new_total_debt = borrowed.mul(env, new_borrow_index);
```

`Ray::mul` panics with `GenericError::MathOverflow` on `i128` overflow. The borrow-index cap at `MAX_BORROW_INDEX_RAY` (common/src/rates/index.rs:15-17) does not prevent this: the cap bounds the index, but the overflow is in `scaled_debt * index`, and for a sufficiently large scaled debt the product overflows even at the capped index. Crucially, once `borrowed * borrow_index > i128::MAX`, the condition is monotone — `borrow_index` never decreases (INV-IDX-01) and `borrowed` only shrinks through `repay`/`seize_positions`, both of which accrue first and therefore panic before they can reduce debt. There is no recovery path; `update_indexes` itself hits the same panic (confirmed by the test at lines 343-355, where `try_withdraw_raw` and `try_repay` both fail with `MATH_OVERFLOW`).

An unprivileged attacker creates the precondition by borrowing a very large position in a high-decimals, high-utilization market (controller `borrow` with a large `amount`, or `multiply`/`create_strategy` which mint debt through the same path), then simply lets time accrue — or accelerates accrual via `update_indexes`, which is permissionless — until the product crosses the `i128` boundary. From that block on, every call touching the market reverts.

### Impact Explanation
Permanent freezing of funds: all suppliers in the bricked market can never withdraw, borrowers can never repay, liquidators can never execute `liquidate`/`clean_bad_debt`, and protocol revenue can never be claimed — every path accrues first. Like the CVE, a single unprivileged actor kills a shared facility used by all other users; unlike a revert-per-call DoS, this one is irreversible. Severity Medium: the freeze is total and permanent, but the precondition demands a very large notional (billions of units of a high-decimals asset at sustained ~98% utilization), and market borrow caps may bound `borrowed` below the overflow region unless caps are set high relative to the asset's decimal scale.

### Likelihood Explanation
Reachable by any unprivileged address able to post collateral and open a large borrow — no privileged role needed. The constraint is economic: the attacker needs enough collateral to borrow notional large enough that `scaled_debt * index` nears `i128::MAX`, and the market's `borrow_cap`/liquidation buffer must permit it. On a low-decimals asset with tight caps this is unreachable; on an 18-decimals asset with lifted caps (as in the repo test), it is only a matter of accrual time, which the attacker does not need to wait out passively since `update_indexes` is open to anyone and accrual is the trigger. The panic requires no competition, no oracle manipulation, and no failed assumptions — deterministic arithmetic.

### Recommendation
Compute accrued interest in a wider type or restructure the formula so the overflow is unreachable: e.g., compute `accrued_interest = borrowed * (new_index - old_index)` (a difference bounded by per-chunk growth) or evaluate `borrowed * new_index` in `I256` and saturate, so accrual never panics on large books. Alternatively, clamp the effective debt value used in the split to `i128` bounds while still writing the capped index, and add a regression test asserting that a market whose debt value exceeds `i128` remains callable for `repay`/`withdraw`/`seize_positions`.

### Proof of Concept
Already encoded in the repo's test suite: `a_whale_market_at_sustained_high_utilization_hits_the_ray_value_ceiling_before_the_index_cap` (tests/test-harness/tests/controller/large_positions_and_long_horizons.rs:321-361) supplies ~1e9 × 10^18 units, borrows 98%, advances time, and shows `update_indexes` panics with `MathOverflow` before the index cap engages — after which both `withdraw` and `repay` panic with the same error. The analogous attacker path is `controller::borrow` (or `multiply`) to establish the oversized debt, then permissionless `update_indexes` once accrual pushes `borrowed * borrow_index` past `i128::MAX`; from that point `supply`/`withdraw`/`repay`/`liquidate`/`clean_bad_debt`/`claim_revenue`/`recapitalize` on that market all abort in `global_sync` → `accrue_step` → `calculate_supplier_rewards` (common/src/rates/index.rs:81).