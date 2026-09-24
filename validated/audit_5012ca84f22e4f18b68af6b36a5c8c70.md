No vulnerability found for this question.

Investigation summary: The reported issue is about a DeFi swap contract using a fixed, non-configurable 90% collateral-value floor (i.e., forcing up to 10% loss tolerance) instead of letting users specify their own slippage limits for DEX/vault interactions.

The closest FRAME analog for AMM-style swaps is `pallet-asset-conversion`, whose extrinsics `swap_exact_tokens_for_tokens` and `swap_tokens_for_exact_tokens` already implement exactly the mitigation the report recommends: callers pass their own `amount_out_min` / `amount_in_max` parameters, and the pallet rejects the swap with `Error::ProvidedMinimumNotSufficientForSwap` / `Error::ProvidedMaximumNotSufficientForSwap` if the user-specified bound isn't met, rather than enforcing a hardcoded tolerance. [1](#0-0) [2](#0-1) [3](#0-2) 

I also checked `pallet-nomination-pools` (the other place where value can be diluted by slashing during unbond/withdraw), but its accounting is share/points-based and directly reflects actual on-chain slashes applied via `do_apply_slash`/`do_slash`, not a discretionary swap-slippage tolerance a user could bound more tightly. [4](#0-3) 

No FRAME/XCM code path was found with the analogous flaw (a hardcoded/non-configurable loss-tolerance threshold applied to a user-attacker-reachable extrinsic without permitting a tighter user-supplied bound), so per the strict output rules I report no vulnerability.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L527-545)
```rust
		pub fn swap_exact_tokens_for_tokens(
			origin: OriginFor<T>,
			path: Vec<Box<T::AssetKind>>,
			amount_in: T::Balance,
			amount_out_min: T::Balance,
			send_to: T::AccountId,
			keep_alive: bool,
		) -> DispatchResult {
			let sender = ensure_signed(origin)?;
			Self::do_swap_exact_tokens_for_tokens(
				sender,
				path.into_iter().map(|a| *a).collect(),
				amount_in,
				Some(amount_out_min),
				send_to,
				keep_alive,
			)?;
			Ok(())
		}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L988-1002)
```rust
			ensure!(amount_in > Zero::zero(), Error::<T>::ZeroAmount);
			if let Some(amount_out_min) = amount_out_min {
				ensure!(amount_out_min > Zero::zero(), Error::<T>::ZeroAmount);
			}

			Self::validate_swap_path(&path)?;
			let path = Self::balance_path_from_amount_in(amount_in, path)?;

			let amount_out = path.last().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_out_min) = amount_out_min {
				ensure!(
					amount_out >= amount_out_min,
					Error::<T>::ProvidedMinimumNotSufficientForSwap
				);
			}
```

**File:** substrate/frame/asset-conversion/src/lib.rs (L1036-1050)
```rust
			ensure!(amount_out > Zero::zero(), Error::<T>::ZeroAmount);
			if let Some(amount_in_max) = amount_in_max {
				ensure!(amount_in_max > Zero::zero(), Error::<T>::ZeroAmount);
			}

			Self::validate_swap_path(&path)?;
			let path = Self::balance_path_from_amount_out(amount_out, path)?;

			let amount_in = path.first().map(|(_, a)| *a).ok_or(Error::<T>::InvalidPath)?;
			if let Some(amount_in_max) = amount_in_max {
				ensure!(
					amount_in <= amount_in_max,
					Error::<T>::ProvidedMaximumNotSufficientForSwap
				);
			}
```

**File:** substrate/frame/nomination-pools/src/lib.rs (L2416-2432)
```rust

			let slash_weight =
				// apply slash if any before withdraw.
				match Self::do_apply_slash(&member_account, None, false) {
					Ok(_) => T::WeightInfo::apply_slash(),
					Err(e) => {
						let no_pending_slash: DispatchResult = Err(Error::<T>::NothingToSlash.into());
						// This is an expected error. We add appropriate fees and continue withdrawal.
						if Err(e) == no_pending_slash {
							T::WeightInfo::apply_slash_fail()
						} else {
							// defensive: if we can't apply slash for some reason, we abort.
							return Err(Error::<T>::Defensive(DefensiveError::SlashNotApplied).into());
						}
					}

				};
```
