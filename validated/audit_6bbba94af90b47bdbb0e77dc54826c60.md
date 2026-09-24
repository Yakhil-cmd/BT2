## Analysis: Analog Found in `pallet-assets`

The reported EVM bug ("mint with `amount = 0` emits a `Minted` event without performing a mint, misleading off-chain integrations") has a direct — and more severe — analog in `pallet-assets`'s `do_mint`/`increase_balance` flow. [1](#0-0) [2](#0-1) 

### Title
`Assets::mint` with `amount = 0` bypasses the `Issuer` permission check and emits a spoofed `Issued` event - (File: `substrate/frame/assets/src/functions.rs`)

### Summary
The extrinsic `pallet_assets::Pallet::mint` is reachable by any signed account and forwards to `Pallet::do_mint`, which first calls `Self::increase_balance(...)` and only *afterwards* unconditionally emits `Event::Issued`. `increase_balance` short-circuits with `Ok(())` when `amount.is_zero()`, *before* it looks up the `Asset` details or invokes the `check` closure that enforces `check_issuer == details.issuer`. Consequently, calling `mint` with `amount = 0` lets any signed caller — not just the asset's `Issuer` — emit an `Issued` event for an arbitrary `asset_id` (even a non-existent one) and an arbitrary `beneficiary`, without ever performing the permission check or the mint itself.

### Finding Description
Entry point (signed extrinsic, no privileged role required): [3](#0-2) 

```rust
pub fn mint(origin, id, beneficiary, #[pallet::compact] amount) -> DispatchResult {
    let origin = ensure_signed(origin)?;
    let beneficiary = T::Lookup::lookup(beneficiary)?;
    let id: T::AssetId = id.into();
    Self::do_mint(id, &beneficiary, amount, Some(origin))?;
    Ok(())
}
```

`do_mint` delegates the permission check to a closure passed into `increase_balance`:
```rust
pub(super) fn do_mint(id, beneficiary, amount, maybe_check_issuer) -> DispatchResult {
    Self::increase_balance(id.clone(), beneficiary, amount, |details| -> DispatchResult {
        if let Some(check_issuer) = maybe_check_issuer {
            ensure!(check_issuer == details.issuer, Error::<T, I>::NoPermission);
        }
        ...
    })?;
    Self::deposit_event(Event::Issued { asset_id: id, owner: beneficiary.clone(), amount });
    Ok(())
}
```

`increase_balance` returns early — *before* fetching `Asset::<T,I>::get(&id)` and *before* invoking the `check` closure — whenever `amount.is_zero()`:
```rust
pub(super) fn increase_balance(id, beneficiary, amount, check) -> DispatchResult {
    if amount.is_zero() {
        return Ok(());
    }
    Self::can_increase(...)...
    Asset::<T, I>::try_mutate(&id, |maybe_details| -> DispatchResult {
        let details = maybe_details.as_mut().ok_or(Error::<T, I>::Unknown)?;
        ...
        check(details)?;   // <- issuer permission check, never reached for amount == 0
        ...
    })?;
    Ok(())
}
```

Because the early return happens before `check(details)` runs, the `NoPermission` guard (`check_issuer == details.issuer`) is skipped entirely. `do_mint` then proceeds to unconditionally call `Self::deposit_event(Event::Issued { asset_id: id, owner: beneficiary.clone(), amount })`. Note that this early return also skips the `Error::<T,I>::Unknown` lookup for the asset, so the `asset_id` need not even exist.

This is analogous to the report's violated invariant ("an event that off-chain systems trust as proof of a mint action must correspond to an actual, authorized mint"), but the FRAME instance is worse: it is not merely a semantically-empty event, it is an **access-control bypass that lets an unprivileged signed account spoof an `Issued` event that appears to originate from a legitimate `Issuer`-authorized mint**, for any asset id/beneficiary combination.

The codebase's own `prdoc/stable2412/pr_5946.prdoc` shows Parity has already fixed the identical class of bug (`Issued{amount:0}`) in `pallet-balances`, and `prdoc/stable2503/pr_6506.prdoc` shows the same fix pattern for `pallet-transaction-payment`'s `FungibleAdapter`. `pallet-assets::do_mint` was not covered by either fix. [4](#0-3) [5](#0-4) 

### Impact Explanation
No balance, supply, or storage state changes as a result of the zero-amount call (this is confirmed — `increase_balance` truly no-ops). The impact is limited to event-log integrity: any signed, unprivileged account can produce a `pallet_assets::Event::Issued { asset_id, owner, amount: 0 }` event for any `asset_id` (existing or fabricated) and any `owner`/`beneficiary`, without holding the `Issuer` role, and without the asset needing to exist. Off-chain indexers, exchanges, bridges, or automated systems that trust `Issued` events (e.g., to credit balances, trigger listings, or confirm issuance authorization) can be misled into believing a legitimate, authorized mint action occurred. Given the explicit precedent of Parity treating `Issued{amount:0}` events as bugs worth patching in `pallet-balances`/`pallet-transaction-payment`, this is a genuine Low/Medium-severity issue, consistent with the original report's assessed severity.

### Likelihood Explanation
High likelihood of occurrence: the `mint` extrinsic is a standard, always-available signed call with `O(1)` weight; a caller need only submit `Assets::mint(origin, id, beneficiary, 0)`. No governance, privileged role, or race condition is required — any account can trigger it at will, repeatedly, at negligible transaction-fee cost.

### Recommendation
In `do_mint` (or in `increase_balance`), check `amount.is_zero()` up front and either:
- Return an error (e.g. reject zero-amount mints), or
- Perform the `Issuer` permission check (and asset-existence lookup) unconditionally before returning early, and skip emitting `Event::Issued` when `amount` is zero — mirroring the fix already applied in `pallet-balances` (`prdoc/stable2412/pr_5946.prdoc`) and `pallet-transaction-payment`'s `FungibleAdapter` (`prdoc/stable2503/pr_6506.prdoc`).

### Proof of Concept
Static-analysis-confirmed control-flow trace (not executed against a live network):
1. Non-issuer signed account `Bob` calls `Assets::mint(RuntimeOrigin::signed(Bob), asset_id, beneficiary, 0)`.
2. `do_mint` calls `increase_balance(asset_id, beneficiary, 0, closure)`.
3. `increase_balance` hits `if amount.is_zero() { return Ok(()); }` on the first line — the `check_issuer == details.issuer` closure and the `Asset::<T,I>::get(&id).ok_or(Error::Unknown)` lookup are never executed.
4. `do_mint` returns `Ok(())` from `increase_balance` and unconditionally executes `Self::deposit_event(Event::Issued { asset_id, owner: beneficiary, amount: 0 })`.
5. Result: extrinsic succeeds (`DispatchResult::Ok`) for a caller with no `Issuer` role, on an `asset_id` that need not exist, producing a spoofed `Issued` event.

This trace is directly supported by the source at [1](#0-0)  and [2](#0-1) ; existing unit test `basic_minting_should_work` only exercises non-zero mints and does not cover this path, so no regression test currently guards against it. [6](#0-5)

### Citations

**File:** substrate/frame/assets/src/functions.rs (L457-477)
```rust
	pub(super) fn do_mint(
		id: T::AssetId,
		beneficiary: &T::AccountId,
		amount: T::Balance,
		maybe_check_issuer: Option<T::AccountId>,
	) -> DispatchResult {
		Self::increase_balance(id.clone(), beneficiary, amount, |details| -> DispatchResult {
			if let Some(check_issuer) = maybe_check_issuer {
				ensure!(check_issuer == details.issuer, Error::<T, I>::NoPermission);
			}
			debug_assert!(details.supply.checked_add(&amount).is_some(), "checked in prep; qed");

			details.supply = details.supply.saturating_add(amount);

			Ok(())
		})?;

		Self::deposit_event(Event::Issued { asset_id: id, owner: beneficiary.clone(), amount });

		Ok(())
	}
```

**File:** substrate/frame/assets/src/functions.rs (L485-497)
```rust
	pub(super) fn increase_balance(
		id: T::AssetId,
		beneficiary: &T::AccountId,
		amount: T::Balance,
		check: impl FnOnce(
			&mut AssetDetails<T::Balance, T::AccountId, DepositBalanceOf<T, I>>,
		) -> DispatchResult,
	) -> DispatchResult {
		if amount.is_zero() {
			return Ok(());
		}

		Self::can_increase(id.clone(), beneficiary, amount, true).into_result()?;
```

**File:** substrate/frame/assets/src/lib.rs (L1033-1045)
```rust
		#[pallet::call_index(6)]
		pub fn mint(
			origin: OriginFor<T>,
			id: T::AssetIdParameter,
			beneficiary: AccountIdLookupOf<T>,
			#[pallet::compact] amount: T::Balance,
		) -> DispatchResult {
			let origin = ensure_signed(origin)?;
			let beneficiary = T::Lookup::lookup(beneficiary)?;
			let id: T::AssetId = id.into();
			Self::do_mint(id, &beneficiary, amount, Some(origin))?;
			Ok(())
		}
```

**File:** prdoc/stable2412/pr_5946.prdoc (L1-15)
```text
# Schema: Polkadot SDK PRDoc Schema (prdoc) v1.0.0
# See doc at https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/prdoc/schema_user.json

title: "[FRAME] fix: Do not emit `Issued { amount: 0 }` event"

doc:
  - audience:
    - Runtime Dev
    - Runtime User
    description: |
      Filter out `Issued` events in `pallet-balances` module when its balance amount is zero.

crates:
  - name: pallet-balances
    bump: patch
```

**File:** prdoc/stable2503/pr_6506.prdoc (L1-10)
```text
title: Zero refund check for FungibleAdapter
doc:
- audience: Runtime User
  description: |-
    `FungibleAdapter` will now check if the _refund amount_ is zero before calling deposit & emitting an event.

    Fixes https://github.com/paritytech/polkadot-sdk/issues/6469.
crates:
- name: pallet-transaction-payment
  bump: patch
```

**File:** substrate/frame/assets/src/tests.rs (L81-109)
```rust
#[test]
fn basic_minting_should_work() {
	build_and_execute(|| {
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), 0, 1, true, 1));
		assert_ok!(Assets::force_create(RuntimeOrigin::root(), 1, 1, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(1), 0, 1, 100));
		System::assert_last_event(RuntimeEvent::Assets(crate::Event::Issued {
			asset_id: 0,
			owner: 1,
			amount: 100,
		}));
		assert_eq!(Assets::balance(0, 1), 100);
		assert_ok!(Assets::mint(RuntimeOrigin::signed(1), 0, 2, 100));
		System::assert_last_event(RuntimeEvent::Assets(crate::Event::Issued {
			asset_id: 0,
			owner: 2,
			amount: 100,
		}));
		assert_eq!(Assets::balance(0, 2), 100);
		assert_eq!(asset_ids(), vec![0, 1, 999]);
		assert_ok!(Assets::mint(RuntimeOrigin::signed(1), 1, 1, 100));
		System::assert_last_event(RuntimeEvent::Assets(crate::Event::Issued {
			asset_id: 1,
			owner: 1,
			amount: 100,
		}));
		assert_eq!(Assets::account_balances(1), vec![(0, 100), (999, 100), (1, 100)]);
	});
}
```
