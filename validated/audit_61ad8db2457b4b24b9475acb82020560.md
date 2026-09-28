### Title
Withdrawable liquidity is not net of accrued protocol revenue — exits can drain the cash backing unclaimed `revenue`, freezing `claim_revenue` - (File: contracts/pool/src/cache/cash.rs)

### Summary
The bug class from the external report — a balance check that treats fee/revenue tokens still sitting on the contract as freely removable liquidity — maps directly onto XOXNO Lending's pool. `Cache::require_reserves` (`contracts/pool/src/cache/cash.rs:15`) gates every outbound flow (`withdraw`, `borrow`, `create_strategy`, `flash_loan`, `claim_revenue`) with a bare `cash >= draw` test. But `cash` includes the tokens that back accrued, still-unclaimed protocol `revenue` shares, which live inside `supplied` (`contracts/pool/src/ops/withdraw.rs:141-142`, `interest::add_protocol_revenue`). Nothing reserves the revenue-backed slice, so ordinary unprivileged exits can take cash that is already spoken for, leaving `claim_revenue` unable to pay out.

### Finding Description
In `LPManager.removeLiquidity`, the protocol fee remains on the balance while the post-removal accounting assumes it was deducted, so valid removals revert. In the XOXNO pool the mirror-image imprecision exists: `require_reserves` compares the requested draw against the full accounting `cash`, which double-counts the revenue backing as available liquidity.

Concretely:

1. `withdraw::accounting` burns the user's shares and calls `gate_and_debit`, which runs `cache.require_reserves(net_transfer)` and `debit_cash(net_transfer)` against raw `cash` (`contracts/pool/src/ops/withdraw.rs:111-118`). Non-liquidation withdrawals additionally pass `require_utilization_below_max`, but neither that guard nor `require_supply_for_debt` reserves revenue-backed cash (`contracts/pool/src/guards.rs:19-73`).
2. Borrows add `require_liquidation_buffer`, which holds back only a flat `LIQUIDATION_BUFFER_BPS` (200 bps) of floored supply (`contracts/pool/src/guards.rs:39-47`) — unrelated to the accrued `revenue` balance, which can exceed that buffer.
3. `revenue::accounting` then calls `cache.burn_claimable_revenue()` and `debit_cash(net_transfer)` (`contracts/pool/src/ops/revenue.rs:39-46`). When `cash` has been drained below the revenue claim, the claimable amount collapses: the harness test `test_claim_revenue_else_branch_when_reserves_fully_drained` (`tests/test-harness/tests/pool/pool_revenue_edge.rs:4-72`) demonstrates exactly this — after reserves are drained to 0, `claim_revenue` transfers 0 while `revenue` stays positive.

So tokens earmarked as protocol revenue are treated as ordinary supplier liquidity by the reserve check, and once they leave the contract the revenue claim cannot be settled.

### Impact Explanation
Theft or temporary freezing of unclaimed yield: accrued protocol revenue becomes unclaimable whenever exits/borrows push `cash` below the revenue backing. `claim_revenue` returns `actual_amount = 0` and burns nothing (`revenue.rs:25-34`), while the `revenue` shares persist. The yield is frozen until fresh supply or repayments rebuild `cash` — and in a market where all remaining cash belongs to withdrawable suppliers, there is no guarantee it ever recovers. The revenue shares also remain embedded in `supplied`, distorting utilization for all subsequent guards.

### Likelihood Explanation
Fully reachable by unprivileged addresses with no special timing. A user supplies, another borrows up to `reserves - buffer`, and a supplier withdraws the residual — the exact sequence in `pool_revenue_edge.rs` uses only `supply`, `borrow`, `withdraw`, `update_indexes`, and `claim_revenue`, all in the permitted entrypoint set. Any market that accrues nonzero `revenue` (reserve_factor > 0, any interest period) can hit it: utilization near `max_utilization` with thin idle cash is the normal operating state, not an edge case. It triggers deterministically whenever `cash < value(revenue shares)` after an exit.

### Recommendation
Exclude revenue-backed tokens from distributable liquidity in the reserve check, analogous to excluding the fee portion in the original report. Concretely, compute the asset value of `cache.revenue` (floored, via the supply index) and have `require_reserves` — or a dedicated guard on `withdraw`/`borrow`/`flash_loan` — require `cash - revenue_value >= draw` instead of `cash >= draw`. Alternatively, exclude revenue shares from the withdrawable/borrowable base in `require_liquidation_buffer` and extend a revenue reserve to withdrawals. The current else-branch in `burn_claimable_revenue` (claim 0 when reserves are empty) is a symptom mitigation, not a fix; the invariant should be that revenue backing never leaves the pool.

### Proof of Concept
Covered by the in-repo harness test `test_claim_revenue_else_branch_when_reserves_fully_drained` (`tests/test-harness/tests/pool/pool_revenue_edge.rs`):

```rust
// supply ALICE 1000 USDC, CAROL 300 USDC; ALICE borrows 700
// accrue 1 year of interest -> revenue > 0
let res_raw = t.pool_client("USDC").get_reserves(&usdc);
let buffer_raw = t.liquidation_buffer_raw("USDC");
t.borrow_raw(BOB, "USDC", res_raw - buffer_raw);   // borrow down to buffer
let residual = t.pool_client("USDC").get_reserves(&usdc);
t.withdraw_raw(CAROL, "USDC", residual);           // withdraw rest -> cash = 0

let claimed = t.claim_revenue("USDC");
assert_eq!(claimed, 0);                            // revenue frozen
// revenue_post >= revenue_pre: shares retained but unpayable
```

`require_reserves` admits each leg because it only checks `cash >= draw` (`cash.rs:15-21`) and never subtracts the `revenue`-backed portion — the same imprecise-balance-check class as the reported `removeLiquidity` miscalculation.