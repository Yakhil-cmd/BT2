No vulnerability found for this question.

The MPTCP bug is a recursive-lock self-deadlock: the same `fallback_lock` spinlock is acquired twice by one thread on one call path (`__mptcp_retrans` holding it, then re-entering `__mptcp_try_fallback` which acquires it again). A structural analog would require a Polkadot SDK code path where a single-threaded execution context re-acquires the same lock/guard (or equivalent reentrancy-guarded critical section) recursively during dispatch of an unprivileged extrinsic, contract call, or XCM message, causing the runtime to hang.

I searched for this pattern across:
- FRAME reentrancy guards — `pallet-message-queue` explicitly documents and enforces a mutex-style reentrancy guard that **errors** (`Error::RecursiveDisallowed`) rather than deadlocking, precisely to avoid this class of bug [1](#0-0) .
- `pallet-contracts` / `pallet-revive` reentrancy protection (`ReentrancyProtection::Strict`/`AllowNext`/`AllowReentry`), which also returns a `DispatchError` (`ReentranceDenied`) on illegal recursion instead of blocking [2](#0-1) [3](#0-2) .
- Related storage-accounting reentrancy bugs in `pallet-revive` (double deposit charge under same-contract reentry, rejected re-entrant instantiate) — these are already-fixed issues documented in `prdoc/pr_12267.prdoc` and `prdoc/pr_12645.prdoc`, not deadlocks, and not currently exploitable [4](#0-3) [5](#0-4) .
- Node/client-side locking primitives (`SharedData`, trie caches, `StorageLock`, statement-store pool) do use real `Mutex`/`RwLock` and explicitly document deadlock risk, but these are not reachable from an unprivileged signed extrinsic, contract call, or XCM message — they are internal node/client synchronization, not runtime dispatch logic driven by attacker-controlled transaction payloads [6](#0-5) .

FRAME's dispatch model executes extrinsics synchronously within a single thread per block (no blocking OS-level locks held across nested calls into the same runtime logic); where recursive execution is possible (message-queue, contracts/revive reentrancy), the implementations use flags/counters checked and reset within the call stack that return errors on illegal recursion rather than acquiring a blocking lock a second time. I found no place where an unprivileged extrinsic, contract call, or XCM message causes the runtime to attempt to re-acquire an already-held lock/guard on the same call stack, which is the essential MPTCP bug-class (recursive/self-deadlock on a critical section). No exploitable analog with a concrete file:line reproduction was found.

### Citations

**File:** substrate/frame/message-queue/src/lib.rs (L59-66)
```rust
//! **Reentrancy**
//!
//! This pallet has two entry points for executing (possibly recursive) logic;
//! [`Pallet::service_queues`] and [`Pallet::execute_overweight`]. Both entry points are guarded by
//! the same mutex to error on reentrancy. The only functions that are explicitly **allowed** to be
//! called by a message processor are: [`Pallet::enqueue_message`] and
//! [`Pallet::enqueue_messages`]. All other functions are forbidden and error with
//! [`Error::RecursiveDisallowed`].
```

**File:** substrate/frame/contracts/src/exec.rs (L1242-1244)
```rust
	fn allows_reentry(&self, id: &AccountIdOf<T>) -> bool {
		!self.frames().any(|f| &f.account_id == id && !f.allows_reentry)
	}
```

**File:** substrate/frame/revive/src/exec.rs (L122-142)
```rust
/// Level of reentrancy protection.
///
/// This needs to be specifed when a contract makes a message call. This way the calling contract
/// can specify the level of re-entrancy protection while the callee (and it's recursive callees) is
/// executing.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ReentrancyProtection {
	/// Don't activate reentrancy protection
	AllowReentry,
	/// Activate strict reentrancy protection. The direct callee and none of its own recursive
	/// callees must be the calling contract.
	Strict,
	/// Activate reentrancy protection where the direct callee can be the same contract as the
	/// caller but none of the recursive callees of the callee must be the caller.
	///
	/// This is used for calls that transfer value but restrict gas so that the callee only has a
	/// stipend gas amount. In Ethereum that is not sufficient for the callee to make another call.
	/// However, due to gas scale differences that guarantee does not automatically hold in revive
	/// and we enforce it explicitly here.
	AllowNext,
}
```

**File:** prdoc/pr_12267.prdoc (L1-24)
```text
title: '[pallet-revive] fix double deposit charge to parent contractinfo'
doc:
- audience: Runtime Dev
  description: |-
    # pallet-revive: fix storage deposit double-count under same-contract reentry

    When a contract writes storage, reenters itself (directly or via an intermediary), and writes storage again, the pre-call write is applied to the contract's persisted `ContractInfo` twice — inflating `storage_items` / `storage_bytes` / `storage_*_deposit`. The corruption is persisted via `insert_contract` and survives across transactions; subsequent `clear_storage` operations under-refund because the inflated counters become the denominator of the pro-rata refund.

    ## What goes wrong

    For `X` writes `K1` → calls itself → writes `K2`:

    1. `push_frame` (`exec.rs:1212-1223`) and the same-contract `cached_info` shortcut (`exec.rs:2150-2160`) clone the parent's `ContractInfo`, preview-apply the parent's pending diff to the clone, and use it as the child's view. The child persists that clone via `insert_contract` on success.
    2. The cache-invalidation matcher (`exec.rs:1616`) then marks the parent's cache `Invalidated`. The parent's next write reloads from storage, which already contains the preview-applied `K1`.
    3. The parent's `finalize()` (`exec.rs:1474-1478`) re-applies its still-pending `own_contribution` (which still contains `K1`) on top of the reloaded info → `K1` counted twice.

    This is a regression from [#10920](https://github.com/paritytech/polkadot-sdk/pull/10920) (commit `1b9ea1c3656`, merged 2026-02-10), which introduced the preview-apply step to make pending writes visible to nested frames for refund pro-rating, but did not consume the parent's `own_contribution`. The existing #10920 regression test (`metering::tests::nested_call_storage_refund` with the `setAndCallClear` fixture) does not catch the case because the parent performs no write after the nested call returns — its cache stays `Invalidated`, the outer pop's `as_contract()` returns `None`, and the diff is never re-applied.

    ## Fix

    Bank the parent's pending diff at the cache-invalidation site so `finalize()` only applies writes recorded afterwards.

    - `RawMeter::bank_pending_changes(contract, info)` (`metering/storage.rs`) — applies the `Alive` diff to `info` once, pushes the resulting deposit as a final `Charge` via the existing `charge_deposit` primitive, and resets `own_contribution`. Two `debug_assert!`s encode invariants: `info.is_some()` whenever the diff is non-empty (otherwise `Diff::update_contract(None)` at `storage.rs:130-134` drops the refund portion and over-charges), and `own_contribution` is `Alive` when banked (on-stack ancestors have not finalized yet, since `finalize` runs at `exec.rs:1474-1478` only at the frame's own pop).
    - `Frame::bank_pending_changes_and_invalidate` (`exec.rs`) — bundles `load → bank → invalidate` so the meter never sees `None` info and the ordering can't be misexpressed. Called from `pop_frame` only when the matcher finds an ancestor with the popped child's `account_id`.
```

**File:** prdoc/pr_12645.prdoc (L1-15)
```text
title: '[pallet-revive] Reject re-entrant instantiate at an in-construction address'
doc:
- audience: Runtime Dev
  description: |-
    Fixes https://github.com/paritytech/polkadot-sdk/issues/12639

    A contract's `ContractInfo` is not written to `AccountInfoOf` until its constructor
    frame pops, so the `is_contract` collision guard in `ContractInfo::new` could not see an
    address that was still being constructed. A re-entrant `CREATE2` with the same salt and
    code (which is nonce independent) therefore resolved to the same address and ran a second
    constructor frame for one account, permanently leaking its consumer reference and code
    refcount and orphaning the second child trie's storage deposit.

    `push_frame` now rejects a nested instantiate whose target address already appears as a
    `Constructor` frame on the call stack, returning `DuplicateContract` (matching EIP-684).
```

**File:** substrate/client/consensus/common/src/shared_data.rs (L171-176)
```rust
/// # Deadlock
///
/// Be aware that this data structure doesn't give you any guarantees that you can not create a
/// deadlock. If you use [`release_mutex`](SharedDataLocked::release_mutex) followed by a call
/// to [`shared_data`](Self::shared_data) in the same thread will make your program dead lock.
/// The same applies when you are using a single threaded executor.
```
