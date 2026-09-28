### Title
Bad-debt supply-index floor leaves stranded supply claims that drain fresh deposits and permanently DoS later withdrawals - (File: contracts/pool/src/interest.rs)

### Summary
In the OpenQ report, obligations ("funding totals") are fixed at competition close and never adjusted, so a subsequent refund leaves the contract owing more than it holds and every remaining claim reverts. The XOXNO Lending analog is the supply-index write-down on bad-debt socialization: `apply_bad_debt_to_supply_index` clamps `supply_index` at `SUPPLY_INDEX_FLOOR_RAW` (RAY/1000) instead of zero, which freezes a fixed residual obligation — every wiped-out supplier keeps a positive claim — while the market holds zero cash. Those stranded claims are never canceled; they are payable in full from the next tokens that enter the market, so a fresh depositor's cash is consumed by a wiped survivor and the depositor's own withdrawal then reverts on `require_reserves`, exactly the "earlier claimant withdraws, remaining claims are owed more than the contract holds" shape of the original bug.

### Finding Description
Bad-debt cleanup writes down `supply_index` so the aggregate supply value shrinks by the bad debt, but the index is floored at a non-zero `SUPPLY_INDEX_FLOOR_RAW` rather than driven to zero. The consequence, demonstrated by `test_raw_cache_seizure_residual_would_drain_fresh_cash_without_supply_guard` in `contracts/pool/tests/interest.rs:430-494`, is:

1. Alice's supply and an equal-sized debt are both wiped. `supply_index` clamps up at RAY/1000, "leaving unburned shares a residual" — Alice keeps a stranded claim while `cash == 0` (her claim is only "masked by require_reserves").
2. Bob deposits `alice_stranded` tokens. Books are immediately insolvent: `total_owed > cash`.
3. Alice withdraws; `resolve_withdrawal`/`require_reserves`/`debit_cash` pay her exactly Bob's fresh deposit.
4. Bob's claim now exceeds `cash` — `cash {} cannot cover Bob's honest claim {}` — and any further exit reverts in `require_reserves` (`contracts/pool/src/cache/cash.rs:15-21`), permanently, unless someone voluntarily recapitalizes.

The invariant docs acknowledge the hole without closing it: INV-ACCT-04 notes recapitalization "cannot restore a written-down index" and "the non-zero supply-index floor can leave residual claims requiring recapitalization" (`docs/reference/invariants.md:128-137`), i.e., the obligation is fixed on the book while the funds backing it are gone — the same root cause as `FundingTotals` never being adjusted post-refund.

Reachability is unprivileged: bad debt is created through ordinary `liquidate`/`clean_bad_debt` flows (permissionless), any address can supply fresh tokens into the wiped market and any wiped survivor can `withdraw`. No admin action is required at any step.

One caveat: the surviving claim is capped at roughly 1/1000 of the wiped position (the index floor), so the drain per incident is bounded by that residual, not the full deposit — this tempers, but does not eliminate, the loss and the permanent withdrawal DoS for whoever is last.

### Impact Explanation
Permanent freezing of user funds and theft-by-arithmetic: a fresh supplier into a market with stranded residual claims has their deposit immediately claimable by wiped-out holders, and their own withdrawal reverts via `require_reserves` since the cash book overstates custody relative to outstanding claims. The market is left structurally insolvent (`floor(supply_value) > cash + ceil(debt_value)`), so new supply is also rejected by the backing check, leaving the market unable to operate until an altruistic `recapitalize` fills the shortfall.

### Likelihood Explanation
Requires a market to hit full bad-debt wipeout — achievable by an unprivileged liquidator calling `liquidate`/`clean_bad_debt` once collateral is insufficient — and then either an unaware depositor supplying into the dead market or a wiped survivor racing to withdraw. Both actors are permissionless; the only mitigating factor is that the stranded residual is bounded by the RAY/1000 index floor, capping the drainable amount.

### Recommendation
When `apply_bad_debt_to_supply_index` writes down the index, fully zero or burn the residual supply claims in the same operation (e.g., drive `supplied` shares to match the post-wipeout index, or zero the index entirely instead of clamping at `SUPPLY_INDEX_FLOOR_RAW`) so the aggregate supply claim never exceeds post-seizure backing — the direct analog of adjusting funding totals after refunds. Alternatively, gate new `supply`/`withdraw` on `floor(supply_value) <= cash + ceil(debt_value)` after write-down so stranded residuals cannot be paid out of fresh deposits.

### Proof of Concept
The repository's own cache-level test encodes the attack end-to-end (`contracts/pool/tests/interest.rs:430-494`):

```rust
// contracts/pool/tests/interest.rs
let bad_debt = cache.unscale_borrow_ceil_ray(borrow_scaled);
apply_bad_debt_to_supply_index(&mut cache, bad_debt);   // index clamps UP at RAY/1000
cache.burn_debt(borrow_scaled);
let alice_stranded = cache.unscale_supply_floor(alice_scaled); // wiped survivor keeps claim
// cash == 0; stranded claim masked only by require_reserves

// Bob deposits alice_stranded tokens
let bob_scaled = cache.calculate_scaled_supply(deposit);
cache.mint_supply(bob_scaled);
cache.credit_cash(deposit);
assert!(total_owed > cache.cash());                     // books insolvent

// Alice withdraws her stranded claim
let (burn, gross) = cache.resolve_withdrawal(i128::MAX, alice_scaled);
cache.require_reserves(gross);
cache.burn_supply(burn);
cache.debit_cash(gross);                                 // Alice extracts Bob's deposit

// Bob's claim now exceeds cash: permanent withdraw DoS
assert!(cache.cash() < cache.unscale_supply_floor(bob_scaled));
```

Concrete user-level sequence: (1) Bob-or-anyone supplies collateral, borrows, collateral price collapses; (2) an unprivileged caller runs `liquidate`/`clean_bad_debt`, socializing bad debt — `supply_index` clamps at the floor, all suppliers retain ~0.1% residual claims; (3) a new supplier calls `supply`/`deposit` into the wiped hub asset; (4) any wiped survivor calls `withdraw` and is paid from the new deposit via `transfer_out` (`contracts/pool/src/cache/cash.rs:46-53`); (5) the new supplier's `withdraw`/`claim` reverts `InsufficientLiquidity` in `require_reserves`, permanently.