No vulnerability found for this question.

I reviewed the `pallet-psm` mint/redeem logic (the closest debt-tracking pallet in this repo) and found no analog to the Isomorph bug. The Isomorph flaw stems from two divergent debt-tracking mappings — `isoUSDLoaned` (principal only, reset to zero on full repayment while interest is still owed) versus `isoUSDLoanAndInterest` (principal + interest) — where the collateral check on new borrows used the wrong ("stale") mapping, letting a user re-borrow into unaccounted-for residual debt.

In `pallet-psm`, debt is tracked through a single storage item, `PsmDebt<T>`, keyed by `(internal_asset, external_asset)`, and both `mint` and `redeem` consistently read/write this same value—there is no split between a "principal" map and a "principal+interest" map that could diverge. [1](#0-0) [2](#0-1) [3](#0-2) 

The `mint` function checks `current_total_psm_debt` and per-asset `current_debt` (both read from `PsmDebt`) before adding `internal_equivalent` and inserting the updated `new_debt` back into the same map. The `redeem` function similarly reads `current_debt` from `PsmDebt`, ensures it covers `effective_internal_net`, and decrements the same map via `saturating_sub`. There is no secondary "loan-without-interest" bookkeeping structure that gets zeroed independently while a parallel "loan+interest" figure remains outstanding — the entire debt lifecycle (mint increases it, redeem decreases it) operates on one canonical value, so the specific "stale principal reset masking residual interest debt" pattern from the Isomorph report has no structural equivalent here.

I did not find any other in-scope pallet (nomination-pools, asset-conversion, etc.) with a comparable dual-tracking debt/interest divergence that a signed extrinsic could exploit to under-collateralize a position.

### Citations

**File:** substrate/frame/psm/src/lib.rs (L458-468)
```rust
	/// Internal-asset debt minted through PSM, per `(internal, external)` pair.
	#[pallet::storage]
	pub type PsmDebt<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AssetId,
		Blake2_128Concat,
		T::AssetId,
		BalanceOf<T>,
		ValueQuery,
	>;
```

**File:** substrate/frame/psm/src/lib.rs (L733-757)
```rust
			let current_total_psm_debt = Self::total_psm_debt(&internal_asset);
			ensure!(
				current_total_psm_debt.saturating_add(internal_equivalent) <= info.max_debt,
				Error::<T>::ExceedsMaxPsmDebt
			);

			let current_debt = PsmDebt::<T>::get(&internal_asset, &external_asset);
			let max_debt = Self::max_asset_debt(&internal_asset, &external_asset, &info);
			let new_debt = current_debt.saturating_add(internal_equivalent);
			ensure!(new_debt <= max_debt, Error::<T>::ExceedsMaxPsmDebt);

			let psm_account = Self::psm_account(&internal_asset);
			T::Fungibles::transfer(
				external_asset.clone(),
				&who,
				&psm_account,
				effective_external,
				Preservation::Expendable,
			)?;
			T::Fungibles::mint_into(internal_asset.clone(), &who, internal_to_user)?;
			if !fee.is_zero() {
				T::Fungibles::mint_into(internal_asset.clone(), &info.fee_destination, fee)?;
			}

			PsmDebt::<T>::insert(&internal_asset, &external_asset, new_debt);
```

**File:** substrate/frame/psm/src/lib.rs (L849-892)
```rust
			let current_debt = PsmDebt::<T>::get(&internal_asset, &external_asset);
			ensure!(current_debt >= effective_internal_net, Error::<T>::InsufficientReserve);

			let reserve = Self::get_reserve(&internal_asset, &external_asset);
			if reserve < external_out {
				defensive!("PSM reserve is less than expected output amount");
				return Err(Error::<T>::Unexpected.into());
			}

			if !fee.is_zero() {
				T::Fungibles::transfer(
					internal_asset.clone(),
					&who,
					&info.fee_destination,
					fee,
					Preservation::Expendable,
				)?;
			}

			if !effective_internal_net.is_zero() {
				T::Fungibles::burn_from(
					internal_asset.clone(),
					&who,
					effective_internal_net,
					Preservation::Expendable,
					Precision::Exact,
					Fortitude::Polite,
				)?;
			}

			let psm_account = Self::psm_account(&internal_asset);
			if !external_out.is_zero() {
				T::Fungibles::transfer(
					external_asset.clone(),
					&psm_account,
					&who,
					external_out,
					Preservation::Expendable,
				)?;
			}

			PsmDebt::<T>::mutate(&internal_asset, &external_asset, |debt| {
				*debt = debt.saturating_sub(effective_internal_net);
			});
```
