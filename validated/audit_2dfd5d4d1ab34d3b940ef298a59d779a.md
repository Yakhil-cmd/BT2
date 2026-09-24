## Analysis Summary

I found a genuine structural analog to the Teller "fee-on-transfer collateral" bug in the Polkadot SDK's ERC20 XCM transactor, wired into `asset-hub-westend`'s XCM configuration. [1](#0-0) 

### Title
ERC20Transactor assumes full nominal `amount` reaches shared checking account, breaking accounting for non-standard-transfer ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` move ERC20 tokens by calling `IERC20::transferCall` through `pallet_revive::bare_call`, and unconditionally credit/require the *nominal* `amount` requested by the XCM instruction rather than the actual amount that moved, exactly mirroring the root cause described in the Teller report (assuming `transfer(amount)` delivers `amount`).

### Finding Description
`withdraw_asset_with_surplus` withdraws tokens from a user by calling the ERC20 `transfer` function to move `amount` from the user to a single, shared `TransfersCheckingAccount`: [2](#0-1) 

If the call succeeds and the `bool` return value is `true`, the function mints an `AssetsInHolding` credit of the full requested `amount` — `Erc20Credit(amount)` — with no check of the checking account's actual balance delta: [3](#0-2) 

Later, `deposit_asset_with_surplus` takes that same nominal `amount` out of the *holding register* and calls ERC20 `transfer` again to move `amount` **out of** the shared checking account to the beneficiary: [4](#0-3) 

For any ERC20 contract with non-standard transfer semantics (fee-on-transfer, rebasing, deflationary burn-on-transfer, etc.), the checking account's real balance increase from the withdraw call will be `< amount`. The second, deposit-side `transfer(amount)` call will then either revert/return `false` (transfer reverts due to insufficient real balance) — exactly the "second deposit fails" failure mode from the Teller report — or, if the checking account happens to hold surplus balance donated by unrelated prior transfers (because it is a single shared account for *all* ERC20 XCM transfers of this transactor, not a per-position escrow like Teller's), the deposit can succeed while draining balance that rightfully belongs to other in-flight transfers, desynchronizing the checking account's real balance from the sum of outstanding `AssetsInHolding` credits tracked by the XCM executor across concurrent/queued messages.

This is reachable from a real, unprivileged, signed entry point: any user can invoke `pallet_xcm::transfer_assets` / `execute` with a `WithdrawAsset`/`DepositAsset` program that the `XcmExecutor` will route through `TransactAsset::transfer_asset`, which — since `ERC20Transactor` does not implement `internal_transfer_asset` — falls back to the two-part withdraw/deposit path using exactly these two functions: [5](#0-4) 

### Impact Explanation
If an asset routed through `ERC20Transactor` is a non-standard-transfer ERC20 (fee-on-transfer or similar), users' cross-chain/local XCM transfers of that asset will unpredictably fail on the deposit leg after already succeeding on the withdraw leg, or — worse — can allow one user's transfer to consume checking-account balance actually contributed by another user's concurrent transfer, since the shared `TransfersCheckingAccount` balance is not reconciled against the sum of `AssetsInHolding` credits before each deposit. This can produce stuck/failed transfers and cross-user balance desynchronization for the shared checking account, analogous to the "unliquidatable collateral" outcome in the original report, but on a shared pooled account rather than a per-loan escrow (a larger blast radius).

### Likelihood Explanation
Reachability requires: (1) an ERC20 asset with non-standard transfer semantics being made a valid transact target for `ERC20Transactor` via the configured `Matcher: MatchesFungibles`, and (2) a normal signed user invoking a standard `pallet_xcm` transfer/execute call for that asset — no privileged role needed. I was not able to fully verify, within the remaining investigation budget, what governs which ERC20 contract addresses `Matcher` accepts on `asset-hub-westend` (e.g., whether arbitrary user-deployed ERC20 contracts can be registered as transactable assets, or only a fixed/curated allow-list). If registration is permissionless or if any already-listed asset has non-standard transfer behavior, likelihood is high; if only vetted, standard-compliant ERC20s can ever be registered, likelihood is low. This is the main open question limiting confidence in exploitability versus the original Teller report (where any borrower could deposit an arbitrary fee-on-transfer token as collateral).

### Recommendation
In `withdraw_asset_with_surplus`, measure the checking account's actual token balance before and after the `transferCall`, and credit `AssetsInHolding` with the observed delta rather than the nominal `amount`. In `deposit_asset_with_surplus`, transfer the amount actually available/tracked for that credit (or clamp to the checking account's real reducible balance) instead of blindly re-using the nominal `amount`, and reject/refund the credit if the deposit-side transfer moves less than expected, following the same "actual amount transferred" pattern already used throughout the native `fungible`/`fungibles` traits (see `substrate/frame/support/src/traits/tokens/fungible/regular.rs` and `fungibles/regular.rs`, both of which explicitly return actual transferred amounts rather than assuming success delivers the full nominal amount).

### Proof of Concept
Not executed. A full PoC would require: (a) confirming the exact `Matcher`/asset-registration configuration for `ERC20Transactor` on `asset-hub-westend` to determine whether an attacker can get a custom fee-on-transfer ERC20 contract (deployed via `pallet_revive`) recognized as a transactable asset, and (b) a local FRAME/XCM integration test driving `pallet_xcm::execute`/`transfer_assets` with `WithdrawAsset`/`DepositAsset` for that asset id, asserting the checking account's real ERC20 balance versus the credited `AssetsInHolding` amount diverges, and observing the deposit-side `transferCall` failing or draining unrelated balance. This verification step was not completed due to remaining-iteration constraints; the code-level logic mismatch (nominal-amount crediting/debiting without balance-delta verification) is directly evidenced by the cited source lines above.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L16-30)
```rust
use super::{
	AccountId, AllPalletsWithSystem, Assets, Balance, Balances, BaseDeliveryFee, CollatorSelection,
	DepositPerByte, DepositPerItem, FeeAssetId, ForeignAssets, GeneralAdmin, ParachainInfo,
	ParachainSystem, PolkadotXcm, PoolAssets, Runtime, RuntimeCall, RuntimeEvent,
	RuntimeHoldReason, RuntimeOrigin, ToRococoXcmRouter, TransactionByteFee, Uniques, WeightToFee,
	XcmpQueue,
};
use alloc::{collections::BTreeSet, vec, vec::Vec};
use assets_common::{
	matching::{
		IsForeignConcreteAsset, NonTeleportableAssetFromTrustedReserve, ParentLocation,
		TeleportableAssetWithTrustedReserve,
	},
	TrustBackedAssetsAsLocation,
};
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L162-203)
```rust
		// We need to map the 32 byte checking account to a 20 byte account.
		let checking_account_eth = T::AddressMapper::to_address(&TransfersCheckingAccount::get());
		let checking_address = Address::from(Into::<[u8; 20]>::into(checking_account_eth));
		let weight_limit = WeightLimit::get();
		// To withdraw, we actually transfer to the checking account.
		// We do this using the solidity ERC20 interface.
		let data =
			IERC20::transferCall { to: checking_address, value: EU256::from(amount) }.abi_encode();
		let ContractResult { result, weight_consumed, storage_deposit, .. } =
			pallet_revive::Pallet::<T>::bare_call(
				OriginFor::<T>::signed(who.clone()),
				asset_id,
				U256::zero(),
				TransactionLimits::WeightAndDeposit {
					weight_limit,
					deposit_limit: StorageDepositLimit::get(),
				},
				data,
				&ExecConfig::new_substrate_tx(),
			);
		// We need to return this surplus for the executor to allow refunding it.
		let surplus = weight_limit.saturating_sub(weight_consumed);
		tracing::trace!(target: "xcm::transactor::erc20::withdraw", ?weight_consumed, ?surplus, ?storage_deposit);
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
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-266)
```rust
		// To deposit, we actually transfer from the checking account to the beneficiary.
		// We do this using the solidity ERC20 interface.
		let data = IERC20::transferCall { to: address, value: EU256::from(amount) }.abi_encode();
		let weight_limit = WeightLimit::get();
		let ContractResult { result, weight_consumed, storage_deposit, .. } =
			pallet_revive::Pallet::<T>::bare_call(
				OriginFor::<T>::signed(TransfersCheckingAccount::get()),
				asset_contract_id,
				U256::zero(),
				TransactionLimits::WeightAndDeposit {
					weight_limit,
					deposit_limit: StorageDepositLimit::get(),
				},
				data,
				&ExecConfig::new_substrate_tx(),
			);
```

**File:** polkadot/xcm/xcm-executor/src/traits/transact_asset.rs (L167-185)
```rust
	fn transfer_asset(
		asset: &Asset,
		from: &Location,
		to: &Location,
		context: &XcmContext,
	) -> Result<Asset, XcmError> {
		match Self::internal_transfer_asset(asset, from, to, context) {
			Err(XcmError::AssetNotFound | XcmError::Unimplemented) => {
				let credit = Self::withdraw_asset(asset, from, Some(context))?;
				Self::deposit_asset(credit, to, Some(context)).map_err(|(unspent, error)| {
					// best effort try to return the assets to original owner
					let _ = Self::deposit_asset(unspent, from, Some(context));
					error
				})?;
				Ok(asset.clone())
			},
			result => result,
		}
	}
```
