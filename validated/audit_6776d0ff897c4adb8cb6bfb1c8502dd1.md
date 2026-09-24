No vulnerability found for this question.

The reported bug class (ERC-20 `approve()` not resetting to zero before setting a new non-zero allowance, which reverts against USDT-style tokens) does not have a viable analog in the current Polkadot SDK codebase. The relevant code — `pallet-assets`' ERC-20 precompile `approve()` in [1](#0-0)  — already implements the exact mitigation the report recommends: when overwriting an existing non-zero allowance, it calls `do_cancel_approval` to zero/remove the prior approval before calling `do_approve_transfer` with the new amount, explicitly to match ERC-20 "set" semantics rather than "add" semantics.

This fix is documented in the prdoc for this change: [2](#0-1) , which states the precompile previously called `do_approve_transfer` directly (accumulating allowances, breaking ERC-20 compliance) and was fixed to cancel-then-reapprove. The same pattern is applied in the `permit` path as well: [3](#0-2) .

Tests confirm this behavior directly, including the overwrite-nonzero-to-nonzero scenario the report warns about: [4](#0-3)  and the zero/revoke path: [5](#0-4) .

Separately, the underlying `pallet-assets` `Approve`/`Mutate` trait implementations (`do_approve_transfer`, `approve_transfer` extrinsic) are native Substrate/FRAME storage mutations, not raw Solidity `IERC20.approve` calls that a hostile token contract could make revert — there is no analog to a "malicious ERC20 token contract" reverting on a non-zero-to-non-zero approve within FRAME's asset pallet itself: [6](#0-5) . The only place where genuine EVM-style `approve()` semantics apply is the precompile layer, which — as shown — was already patched to avoid this exact issue.

### Citations

**File:** substrate/frame/assets/precompiles/src/lib.rs (L396-419)
```rust
		} else {
			// If there's an existing non-zero allowance, cancel it first so we
			// overwrite (not accumulate) — matching ERC-20 spec semantics.
			// NOTE: This does not mitigate the well-known ERC-20 approve front-running
			// race condition. Callers concerned about this should approve to 0 first,
			// or use increaseAllowance/decreaseAllowance if available.
			if !current.is_zero() {
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = worst_case;
			} else {
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
			}
			pallet_assets::Pallet::<Runtime, Instance>::do_approve_transfer(
				asset_id,
				&owner_account,
				&spender_account,
				new_amount,
			)?;
		}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L550-593)
```rust
				let actual_weight;
				if new_amount.is_zero() {
					if !current.is_zero() {
						// clear approval if it exists, to match ERC-20 semantics of setting
						// allowance to 0
						pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
							&asset_id,
							&owner_account,
							&spender_account,
						)?;
						actual_weight = use_permit_weight
							.saturating_add(<Runtime as Config<Instance>>::WeightInfo::allowance())
							.saturating_add(
								<Runtime as Config<Instance>>::WeightInfo::cancel_approval(),
							);
					} else {
						// noop: set allowance to zerowhen it is already zero
						actual_weight = use_permit_weight
							.saturating_add(<Runtime as Config<Instance>>::WeightInfo::allowance());
					}
				} else {
					if !current.is_zero() {
						// If there's an existing non-zero allowance, cancel it first
						pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
							&asset_id,
							&owner_account,
							&spender_account,
						)?;
						actual_weight = worst_case;
					} else {
						// set new approval
						actual_weight = use_permit_weight
							.saturating_add(<Runtime as Config<Instance>>::WeightInfo::allowance())
							.saturating_add(
								<Runtime as Config<Instance>>::WeightInfo::approve_transfer(),
							);
					}
					pallet_assets::Pallet::<Runtime, Instance>::do_approve_transfer(
						asset_id,
						&owner_account,
						&spender_account,
						new_amount,
					)?;
				}
```

**File:** prdoc/stable2606/pr_11279.prdoc (L1-10)
```text
title: '[pallet-assets] Fix ERC-20 approve semantics in precompile'
doc:
- audience: Runtime Dev
  description: "The ERC-20 approve(spender, amount) spec sets the allowance to amount.\
    \ The precompile was calling do_approve_transfer, which adds to the existing allowance\
    \ \u2014 breaking ERC-20 compliance.\n\nThis PR fixes the precompile's approve\
    \ to use set semantics by composing existing pallet-assets primitives: when\
    \ overwriting a non-zero allowance, the existing approval is cancelled first\
    \ so the new value replaces (not accumulates with) the old one.\n\nAlso extracts\
    \ do_cancel_approval from pallet-assets for reuse by the precompile."
```

**File:** substrate/frame/assets/precompiles/src/tests.rs (L356-395)
```rust
#[test_case(PRECOMPILE_ADDRESS_PREFIX)]
#[test_case(PRECOMPILE_ADDRESS_PREFIX_FOREIGN)]
fn approve_set_and_revoke(asset_index: u16) {
	use frame_support::traits::fungibles::approvals::Inspect;

	new_test_ext().execute_with(|| {
		let asset_id = 0u32;
		let asset_addr = H160::from(set_prefix_in_address(asset_index));

		let owner = 123456789u64;
		let spender = 987654321u64;

		Balances::make_free_balance_be(&owner, 100);
		Balances::make_free_balance_be(&spender, 100);

		let spender_addr = <Test as pallet_revive::Config>::AddressMapper::to_address(&spender);

		setup_asset_for_prefix(asset_id, asset_index);
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), asset_id, owner, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(owner), asset_id, owner, 100));

		let deposit: u128 = <Test as pallet_assets::Config>::ApprovalDeposit::get();
		assert_eq!(Balances::reserved_balance(&owner), 0);

		// First approve: set allowance to 100 (from zero — allowed).
		call_approve(owner, asset_addr, spender_addr, U256::from(100));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 100);
		assert_eq!(Balances::reserved_balance(&owner), deposit);

		// Approve to 0: must revoke the allowance entirely and unreserve the deposit.
		call_approve(owner, asset_addr, spender_addr, U256::from(0));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 0);
		assert_eq!(Balances::reserved_balance(&owner), 0);

		// Re-approve to 50 after zeroing — allowed, deposit reserved again.
		call_approve(owner, asset_addr, spender_addr, U256::from(50));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 50);
		assert_eq!(Balances::reserved_balance(&owner), deposit);
	});
}
```

**File:** substrate/frame/assets/precompiles/src/tests.rs (L494-536)
```rust
/// Directly overwriting a non-zero allowance with a different non-zero value must use set
/// semantics (cancel + re-approve). The allowance must equal the new value — not the sum of
/// old and new — and only a single deposit should be reserved.
#[test_case(PRECOMPILE_ADDRESS_PREFIX)]
#[test_case(PRECOMPILE_ADDRESS_PREFIX_FOREIGN)]
fn approve_nonzero_to_nonzero(asset_index: u16) {
	use frame_support::traits::fungibles::approvals::Inspect;

	new_test_ext().execute_with(|| {
		let asset_id = 0u32;
		let asset_addr = H160::from(set_prefix_in_address(asset_index));

		let owner = 123456789u64;
		let spender = 987654321u64;

		Balances::make_free_balance_be(&owner, 100);
		Balances::make_free_balance_be(&spender, 100);

		let spender_addr = <Test as pallet_revive::Config>::AddressMapper::to_address(&spender);

		setup_asset_for_prefix(asset_id, asset_index);
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), asset_id, owner, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(owner), asset_id, owner, 100));

		let deposit: u128 = <Test as pallet_assets::Config>::ApprovalDeposit::get();

		// Approve 100 (0 → 100).
		call_approve(owner, asset_addr, spender_addr, U256::from(100));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 100);
		assert_eq!(Balances::reserved_balance(&owner), deposit);

		// Overwrite with 50 directly (100 → 50), no zeroing in between.
		call_approve(owner, asset_addr, spender_addr, U256::from(50));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 50);
		// Deposit reserved exactly once — cancel unreserved the old one, approve re-reserved.
		assert_eq!(Balances::reserved_balance(&owner), deposit);

		// Overwrite upward (50 → 200) to confirm it works in both directions.
		call_approve(owner, asset_addr, spender_addr, U256::from(200));
		assert_eq!(Assets::allowance(asset_id, &owner, &spender), 200);
		assert_eq!(Balances::reserved_balance(&owner), deposit);
	});
}
```

**File:** substrate/frame/assets/src/impl_fungibles.rs (L314-325)
```rust
impl<T: Config<I>, I: 'static> fungibles::approvals::Mutate<<T as SystemConfig>::AccountId>
	for Pallet<T, I>
{
	// Approve spending tokens from a given account
	fn approve(
		asset: T::AssetId,
		owner: &<T as SystemConfig>::AccountId,
		delegate: &<T as SystemConfig>::AccountId,
		amount: T::Balance,
	) -> DispatchResult {
		Self::do_approve_transfer(asset, owner, delegate, amount)
	}
```
