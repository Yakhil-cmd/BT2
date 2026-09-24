### Title
Boundary mismatch between `do_claim_swap` and `do_cancel_swap` deadline checks allows unauthorized swap cancellation at `now == deadline` - (File: `substrate/frame/nfts/src/features/atomic_swap.rs`)

### Summary
`pallet-nfts`' atomic-swap feature stores a single `deadline` field (`PendingSwap::deadline`) that is consulted by two independent, permissionless-to-call extrinsics with inconsistent boundary semantics: `claim_swap` treats `now == deadline` as *still valid* while `cancel_swap` treats `now == deadline` as *already expired*, at which point it skips the item-owner permission check entirely.

### Finding Description
`do_claim_swap` accepts a claim whenever the current block is not yet strictly past the deadline: [1](#0-0) 

`do_cancel_swap`, however, only requires the caller to be the item owner while `swap.deadline > now` is true; once `now` reaches the deadline (i.e. `deadline > now` becomes `false`), the permission check is skipped and *any* account may cancel the swap: [2](#0-1) 

Both extrinsics are reachable by ordinary signed accounts (`claim_swap`, `cancel_swap` are public dispatchables backed by these `do_*` functions), with no privileged origin required. At the exact block where `block_number == swap.deadline`:
- `do_claim_swap`'s check `now <= swap.deadline` evaluates `true` → the swap is still "live" from the claimer's perspective.
- `do_cancel_swap`'s check `swap.deadline > now` evaluates `false` → the swap is treated as "already expired" from the canceller's perspective, bypassing the `item.owner == caller` permission check.

This is the same class of bug as the Gondi `_baseLoanChecks` report: a single expiry/deadline value is compared with mismatched strict/non-strict operators across two code paths that are supposed to be mutually exclusive (valid vs. expired), so at the exact boundary timestamp both paths simultaneously consider the object in their favorable state.

### Impact Explanation
At `now == deadline`, any account (not the item owner, not the counterparty) can call `cancel_swap` to remove the `PendingSwapOf` entry without holding item ownership, `Error::<T, I>::NoPermission` being bypassed by the boundary flip. This does not transfer any NFT or currency and does not corrupt or leak funds — `do_cancel_swap` only removes the storage entry — so it cannot lock NFTs/funds the way the Gondi loan bug could. The practical effect is a permission-check bypass that lets an unrelated third party grief the swap creator by removing their live offer one block earlier than the "clean" expiry semantics would suggest, and it can race a legitimate `claim_swap` call within the same block. Because no asset loss, unbacked issuance, or permanent freezing results, this does not meet the Critical/High bar; it is a genuine but Low-severity access-control boundary bug.

### Likelihood Explanation
Requires only a normal signed account, no privileged role, and requires the attacker (or an opportunistic third party) to submit `cancel_swap` in the exact block equal to `swap.deadline`. This is deterministically reachable (deadline is public via the `SwapCreated`/`PendingSwapOf` storage and events), but the practical incentive to exploit is low since the swap would expire on its own one block later anyway.

### Recommendation
Align the two comparisons to the same inclusive/exclusive convention, e.g. change `do_cancel_swap`'s guard to `swap.deadline >= now` (mirroring `do_claim_swap`'s `now <= swap.deadline`) so that ownership permission is still required for the whole window during which a claim would succeed:
```rust
if swap.deadline >= now {
    let item = Item::<T, I>::get(&offered_collection_id, &offered_item_id)
        .ok_or(Error::<T, I>::UnknownItem)?;
    ensure!(item.owner == caller, Error::<T, I>::NoPermission);
}
```

### Proof of Concept
Guards inspected and confirmed via static reading of source (no live network execution performed):
- `do_claim_swap` guard: `ensure!(now <= swap.deadline, Error::<T, I>::DeadlineExpired);` [1](#0-0) 
- `do_cancel_swap` guard: `if swap.deadline > now { ...ensure!(item.owner == caller, NoPermission)... }` [3](#0-2) 

Minimal reproduction sketch (analogous to existing `claim_swap_should_work` test at `substrate/frame/nfts/src/tests.rs:2828-2919`, not executed here):
1. `user_1` creates a swap with `duration = 2` at block 1 → `deadline = 3`.
2. Advance to block `3` (`System::set_block_number(3)`).
3. Have an unrelated `user_3` (not the item owner, not the counterparty) call `cancel_swap` → succeeds because `swap.deadline (3) > now (3)` is `false`, skipping the `NoPermission` check.
4. In the same block, `user_2` (the intended counterparty) calling `claim_swap` would independently satisfy `now (3) <= swap.deadline (3)` and could have claimed instead — demonstrating the two paths disagree about whether block 3 is "expired."

I did not run this against a live/test harness; this is a static-analysis-confirmed boundary mismatch, not an executed PoC. Severity is assessed as Low because no funds/NFTs are frozen or stolen — `do_cancel_swap` only deletes the pending-swap storage entry, leaving the offered item with its rightful owner.

### Citations

**File:** substrate/frame/nfts/src/features/atomic_swap.rs (L119-129)
```rust
		let swap = PendingSwapOf::<T, I>::get(&offered_collection_id, &offered_item_id)
			.ok_or(Error::<T, I>::UnknownSwap)?;

		let now = T::BlockNumberProvider::current_block_number();
		if swap.deadline > now {
			let item = Item::<T, I>::get(&offered_collection_id, &offered_item_id)
				.ok_or(Error::<T, I>::UnknownItem)?;
			ensure!(item.owner == caller, Error::<T, I>::NoPermission);
		}

		PendingSwapOf::<T, I>::remove(&offered_collection_id, &offered_item_id);
```

**File:** substrate/frame/nfts/src/features/atomic_swap.rs (L190-191)
```rust
		let now = T::BlockNumberProvider::current_block_number();
		ensure!(now <= swap.deadline, Error::<T, I>::DeadlineExpired);
```
