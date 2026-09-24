No vulnerability found for this question.

The report concerns Solidity code that calls `.approve()` on an external ERC-20 token without checking the returned `bool`, violating EIP-20's requirement that callers must handle `false` returns. Searching the polkadot-sdk codebase for an analogous pattern — code that issues outbound approve/transfer calls to an ERC-20-like interface without validating the result — found no match:

- The only place in-repo that makes outbound calls against the `IERC20` interface is `ERC20Transactor` in `erc20_transactor.rs`, and both its `withdraw_asset_with_surplus` and `deposit_asset_with_surplus` methods explicitly check `return_value.did_revert()` and decode/validate the boolean return value from `transferCall`, correctly branching to error paths on `false` or decode failure. [1](#0-0) [2](#0-1) 
- Neither `withdraw_asset_with_surplus` nor `deposit_asset_with_surplus` issue any `approve` call at all — only `transferCall` is used, so there is no unchecked-approve outbound call to analyze. [3](#0-2) 
- The `pallet-assets-precompiles` code (`substrate/frame/assets/precompiles/src/lib.rs`) implements the *receiving* side of `approve`/`permit` (i.e., it is the ERC-20 contract being called, not a caller invoking approve on some other token), and it always returns `true` and properly composes pallet-assets primitives with explicit error propagation via `?`. [4](#0-3) 

There is no reachable, attacker-controlled entry point in polkadot-sdk where an outbound `approve()`-style call's boolean return value is silently ignored in a way that could cause loss or integrity break — the existing outbound calls are the opposite case (defensively checked). No demonstrable Polkadot SDK analog exists for this EIP-20-compliance finding.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-169)
```rust
		// To withdraw, we actually transfer to the checking account.
		// We do this using the solidity ERC20 interface.
		let data =
			IERC20::transferCall { to: checking_address, value: EU256::from(amount) }.abi_encode();
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L185-208)
```rust
		if let Ok(return_value) = result {
			tracing::trace!(target: "xcm::transactor::erc20::withdraw", ?return_value, "Return value by withdraw_asset");
			if return_value.did_revert() {
				tracing::debug!(target: "xcm::transactor::erc20::withdraw", "ERC20 contract reverted");
				Err(XcmError::FailedToTransactAsset("ERC20 contract reverted"))
			} else {
				let is_success = IERC20::transferCall::abi_decode_returns_validate(&return_value.data).map_err(|error| {
					tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?error, "ERC20 contract result couldn't decode");
					XcmError::FailedToTransactAsset("ERC20 contract result couldn't decode")
				})?;
				if is_success {
					tracing::trace!(target: "xcm::transactor::erc20::withdraw", "ERC20 contract was successful");
					Ok((
						AssetsInHolding::new_from_fungible_credit(
							what.id.clone(),
							Box::new(Erc20Credit(amount)),
						),
						surplus,
					))
				} else {
					tracing::debug!(target: "xcm::transactor::erc20::withdraw", "contract transfer failed");
					Err(XcmError::FailedToTransactAsset("ERC20 contract transfer failed"))
				}
			}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L270-298)
```rust
		if let Ok(return_value) = result {
			tracing::trace!(target: "xcm::transactor::erc20::deposit", ?return_value, "Return value");
			if return_value.did_revert() {
				tracing::debug!(target: "xcm::transactor::erc20::deposit", "Contract reverted");
				Err((what, XcmError::FailedToTransactAsset("ERC20 contract reverted")))
			} else {
				match IERC20::transferCall::abi_decode_returns_validate(&return_value.data) {
					Ok(true) => {
						tracing::trace!(target: "xcm::transactor::erc20::deposit", "ERC20 contract was successful");
						Ok(surplus)
					},
					Ok(false) => {
						tracing::debug!(target: "xcm::transactor::erc20::deposit", "contract transfer failed");
						Err((
							what,
							XcmError::FailedToTransactAsset("ERC20 contract transfer failed"),
						))
					},
					Err(error) => {
						tracing::debug!(target: "xcm::transactor::erc20::deposit", ?error, "ERC20 contract result couldn't decode");
						Err((
							what,
							XcmError::FailedToTransactAsset(
								"ERC20 contract result couldn't decode",
							),
						))
					},
				}
			}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L352-432)
```rust
	fn approve(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::approveCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		use frame_support::traits::fungibles::approvals::Inspect as ApprovalsInspect;

		// Reserve worst-case gas upfront, then refund the unused portion.
		let worst_case = <Runtime as Config<Instance>>::WeightInfo::allowance()
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval())
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
		let charged = env.charge(worst_case)?;

		let owner = Self::caller(env)?;
		let owner_account =
			<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&owner);
		let spender: H160 = call.spender.into_array().into();
		let spender_account = env.to_account_id(&spender);
		// Saturate: `type(uint256).max` is the standard "infinite allowance" idiom and must
		// not revert at the conversion boundary.
		let new_amount: <Runtime as Config<Instance>>::Balance = call.value.unique_saturated_into();

		let current = pallet_assets::Pallet::<Runtime, Instance>::allowance(
			asset_id.clone(),
			&owner_account,
			&spender_account,
		);

		let actual_weight;
		if new_amount.is_zero() {
			if !current.is_zero() {
				// Revoke: use the pallet's cancel logic to remove the approval and
				// unreserve the deposit.
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval());
			} else {
				// 0→0 no-op: only the allowance read was needed.
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance();
			}
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
		env.adjust_gas(charged, actual_weight);

		Self::deposit_event(
			env,
			IERC20Events::Approval(IERC20::Approval {
				owner: owner.0.into(),
				spender: call.spender,
				value: call.value,
			}),
		)?;

		Ok(IERC20::approveCall::abi_encode_returns(&true))
	}
```
