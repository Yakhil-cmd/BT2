No vulnerability found for this question.

The reported issue itself is not a valid vulnerability pattern to begin with: `getLoanLender` in the referenced Solidity contract is a `view` function that performs no state mutation before or after the external `ownerOf` call, so there is no state to corrupt via reentrancy — Sherlock audit reports of this class are commonly rejected as false positives for exactly this reason.

Searching for an analogous pattern in polkadot-sdk (pallet-contracts and pallet-revive, which are the closest FRAME components to EVM-style contract calling semantics) shows the opposite of an unguarded external call: both pallets implement explicit, default-deny reentrancy protection. In `pallet-revive`, `ReentrancyProtection::Strict` is the default enforcement level for PVM/Wasm calls and is checked via `allows_reentry` before pushing a new call frame [1](#0-0) , with the enum documented at [2](#0-1) . `pallet-contracts` has the equivalent `allows_reentry` check gating `Ext::call` [3](#0-2) , and both pallets have dedicated regression tests confirming denial of reentrant calls (`call_reentry_direct_recursion`, `call_deny_reentry`) [4](#0-3) [5](#0-4) .

There is no "view/read-only external call to a manager/registry contract" pattern in polkadot-sdk analogous to `getLoanLender`'s `lenderManager.ownerOf` call that lacks reentrancy guarding and mutates state as a result — the closest real, previously-identified issues in this area (e.g., the storage-deposit double-count in same-contract reentry, PR #12267) concern accounting bugs in the metering logic during *legitimate* reentrant calls, not an unguarded external view call enabling state corruption [6](#0-5) . That issue is unrelated to the reported bug class (it's a storage-deposit accounting bug, not an attacker-exploitable state-corruption-via-reentrancy in a view/lookup path), and does not map onto the reported vulnerability's actual mechanism.

No reachable, attacker-controlled entry point in polkadot-sdk production code was found that reproduces the reported bug class — an unguarded external call in a read-only/view-style lookup function enabling reentrancy-based state manipulation.

### Citations

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

**File:** substrate/frame/revive/src/exec.rs (L2249-2270)
```rust
		// Before pushing the new frame: Protect the caller contract against reentrancy attacks.
		// It is important to do this before calling `allows_reentry` so that a direct recursion
		// is caught by it.

		if allows_reentry == ReentrancyProtection::Strict {
			self.top_frame_mut().allows_reentry = false;
		}

		let try_call = || {
			// Enable read-only access if requested; cannot disable it if already set.
			let is_read_only = read_only || self.is_read_only();

			// We can skip the stateful lookup for pre-compiles.
			let dest = if <AllPrecompiles<T>>::get::<Self>(dest_addr.as_fixed_bytes()).is_some() {
				T::AddressMapper::to_fallback_account_id(dest_addr)
			} else {
				T::AddressMapper::to_account_id(dest_addr)
			};

			if !self.allows_reentry(&dest) {
				return Err(<Error<T>>::ReentranceDenied.into());
			}
```

**File:** substrate/frame/contracts/src/exec.rs (L1261-1280)
```rust
	fn call(
		&mut self,
		gas_limit: Weight,
		deposit_limit: BalanceOf<T>,
		to: T::AccountId,
		value: BalanceOf<T>,
		input_data: Vec<u8>,
		allows_reentry: bool,
		read_only: bool,
	) -> Result<ExecReturnValue, ExecError> {
		// Before pushing the new frame: Protect the caller contract against reentrancy attacks.
		// It is important to do this before calling `allows_reentry` so that a direct recursion
		// is caught by it.
		self.top_frame_mut().allows_reentry = allows_reentry;

		let try_call = || {
			if !self.allows_reentry(&to) {
				return Err(<Error<T>>::ReentranceDenied.into());
			}

```

**File:** substrate/frame/contracts/src/exec.rs (L3116-3164)
```rust
	#[test]
	fn call_reentry_direct_recursion() {
		// call the contract passed as input with disabled reentry
		let code_bob = MockLoader::insert(Call, |ctx, _| {
			let dest = Decode::decode(&mut ctx.input_data.as_ref()).unwrap();
			ctx.ext
				.call(Weight::zero(), BalanceOf::<Test>::zero(), dest, 0, vec![], false, false)
		});

		let code_charlie = MockLoader::insert(Call, |_, _| exec_success());

		ExtBuilder::default().build().execute_with(|| {
			let schedule = <Test as Config>::Schedule::get();
			place_contract(&BOB, code_bob);
			place_contract(&CHARLIE, code_charlie);
			let contract_origin = Origin::from_account_id(ALICE);
			let mut storage_meter =
				storage::meter::Meter::new(&contract_origin, Some(0), 0).unwrap();

			// Calling another contract should succeed
			assert_ok!(MockStack::run_call(
				contract_origin.clone(),
				BOB,
				&mut GasMeter::<Test>::new(GAS_LIMIT),
				&mut storage_meter,
				&schedule,
				0,
				CHARLIE.encode(),
				None,
				Determinism::Enforced
			));

			// Calling into oneself fails
			assert_err!(
				MockStack::run_call(
					contract_origin,
					BOB,
					&mut GasMeter::<Test>::new(GAS_LIMIT),
					&mut storage_meter,
					&schedule,
					0,
					BOB.encode(),
					None,
					Determinism::Enforced
				)
				.map_err(|e| e.error),
				<Error<Test>>::ReentranceDenied,
			);
		});
```

**File:** substrate/frame/revive/src/exec/tests.rs (L1664-1712)
```rust
#[test]
fn call_reentry_direct_recursion() {
	// call the contract passed as input with disabled reentry
	let code_bob = MockLoader::insert(Call, |ctx, _| {
		let dest = H160::from_slice(ctx.input_data.as_ref());
		ctx.ext
			.call(
				&Default::default(),
				&dest,
				U256::zero(),
				vec![],
				ReentrancyProtection::Strict,
				false,
			)
			.map(|_| ctx.ext.last_frame_output().clone())
	});

	let code_charlie = MockLoader::insert(Call, |_, _| exec_success());

	ExtBuilder::default().build().execute_with(|| {
		place_contract(&BOB, code_bob);
		place_contract(&CHARLIE, code_charlie);
		let origin = Origin::from_account_id(ALICE);
		let mut meter = TransactionMeter::<Test>::new_from_limits(WEIGHT_LIMIT, 0).unwrap();

		// Calling another contract should succeed
		assert_ok!(MockStack::run_call(
			origin.clone(),
			BOB_ADDR,
			&mut meter,
			U256::zero(),
			CHARLIE_ADDR.as_bytes().to_vec(),
			&ExecConfig::new_substrate_tx(),
		));

		// Calling into oneself fails
		assert_err!(
			MockStack::run_call(
				origin,
				BOB_ADDR,
				&mut meter,
				U256::zero(),
				BOB_ADDR.as_bytes().to_vec(),
				&ExecConfig::new_substrate_tx(),
			)
			.map_err(|e| e.error),
			<Error<Test>>::ReentranceDenied,
		);
	});
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
