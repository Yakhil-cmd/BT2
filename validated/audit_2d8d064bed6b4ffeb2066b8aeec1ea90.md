No vulnerability found for this question.

Substrate's `pallet-asset-conversion` swap extrinsics (`swap_exact_tokens_for_tokens`, `swap_tokens_for_exact_tokens`) already provide the equivalent slippage protection the report is about, via `amount_out_min`/`amount_in_max` parameters that revert with `Error::<T>::ProvidedMinimumNotSufficientForSwap` if the swap can't meet the caller's constraint, executed atomically inside `do_swap_exact_tokens_for_tokens`/`do_swap_tokens_for_exact_tokens`. [1](#0-0) [2](#0-1) 

The Uniswap-style "deadline" pattern exists to protect against a transaction that is signed off-chain and sits pending in a mempool for an extended, attacker-influenced period before execution, during which the price can drift unfavorably. FRAME extrinsics don't have this analog gap: Substrate transactions already carry a mortality/era window enforced by `frame_system::CheckMortality` (formerly `CheckEra`), which bounds how long a signed extrinsic can remain valid for inclusion before it is rejected — this is the FRAME-native equivalent of a deadline, and it applies uniformly to all signed calls, not something the pallet author would need to reimplement per-call. Combined with the existing `amount_out_min`/`amount_in_max` slippage checks, there is no missing-check gap analogous to the USSD Solidity issue (which lacked both a deadline and had `amountOutMinimum: 0`, i.e., no slippage protection at all).

I did not find any swap-like extrinsic in the codebase (asset-conversion, atomic-swap, NFTs' `create_swap`) that omits a deadline/slippage-equivalent check where FRAME's own mortality mechanism doesn't already cover the underlying "stale pending transaction executes at bad price" risk. The NFT and Balances `atomic-swap` pallets even carry their own explicit `deadline`/`duration` fields checked against `T::BlockNumberProvider::current_block_number()`. [3](#0-2) 

Given no reachable, unguarded deadline/slippage gap analogous to the reported issue exists in this codebase's swap-related extrinsics, this report has no supported FRAME/XCM analog.

### Citations

**File:** substrate/frame/asset-conversion/src/lib.rs (L519-545)
```rust
		/// Swap the exact amount of `asset1` into `asset2`.
		/// `amount_out_min` param allows you to specify the min amount of the `asset2`
		/// you're happy to receive.
		///
		/// [`AssetConversionApi::quote_price_exact_tokens_for_tokens`] runtime call can be called
		/// for a quote.
		#[pallet::call_index(3)]
		#[pallet::weight(T::WeightInfo::swap_exact_tokens_for_tokens(path.len() as u32))]
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

**File:** substrate/frame/asset-conversion/src/lib.rs (L988-1004)
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

			Self::swap(&sender, &path, &send_to, keep_alive)?;
```

**File:** substrate/frame/nfts/src/features/atomic_swap.rs (L190-191)
```rust
		let now = T::BlockNumberProvider::current_block_number();
		ensure!(now <= swap.deadline, Error::<T, I>::DeadlineExpired);
```
