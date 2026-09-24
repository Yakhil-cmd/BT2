## Analysis Summary

The Taurus report's core defect — code that assumes `transferFrom`/`transfer` always moves the *exact* requested amount and credits internal accounting with that nominal amount instead of the actually-received delta — has a concrete analog in the polkadot-sdk `ERC20Transactor`, the XCM `TransactAsset` implementation used to treat pallet-revive-deployed ERC20 contracts as XCM-transferable assets on Asset Hub. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Fee-on-transfer / non-standard ERC20 tokens break 1:1 reserve backing in `ERC20Transactor`, causing unbacked derivative-asset issuance and eventual redemption insolvency - (File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `::deposit_asset_with_surplus` implement XCM's `TransactAsset` for pallet-revive-hosted ERC20 tokens by calling the token's `transfer()`/`transferFrom`-equivalent Solidity function and then **unconditionally** crediting the XCM `AssetsInHolding` register (or treating a beneficiary as fully paid) with the exact `amount` requested in the XCM `Asset`, without checking the checking-account's/beneficiary's actual balance delta before vs. after the call.

### Finding Description
`withdraw_asset_with_surplus` moves `amount` of an ERC20 token from a user to `TransfersCheckingAccount` (the local "reserve" holding all locked ERC20 collateral) via a bare EVM call to `IERC20::transfer`: [4](#0-3) 

If the call succeeds and decodes `true`, the function unconditionally builds `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` — i.e., it credits the XCM executor's holding register with the full nominal `amount`, not the actual increase in `TransfersCheckingAccount`'s balance.

Symmetrically, `deposit_asset_with_surplus` unlocks tokens by calling `IERC20::transfer(beneficiary, amount)` **from** the checking account, and treats a `true` return as fully satisfying the deposit of `amount`: [5](#0-4) 

Neither function reads `balanceOf(checking_account)`/`balanceOf(beneficiary)` before and after the transfer to confirm that exactly `amount` moved. This is the same missing invariant flagged in the original report ("balance-before/after" check).

`ERC20Transactor` is wired into `AssetTransactors` on Asset Hub Westend, alongside the native/foreign-asset transactors, so it is live production XCM asset-handling logic, not test/mock code: [6](#0-5) 

pallet-revive lets any unprivileged signed account permissionlessly deploy arbitrary EVM bytecode implementing `IERC20`, including a token whose `transfer`/`_update` logic burns or redirects part of the value (fee-on-transfer, deflationary, or rebasing semantics), exactly analogous to the "attacker deploys a normal-looking but fee-charging ERC20" precondition in the original report. Reserve/local-transfer flows built on top of this transactor (e.g., `pallet_xcm::transfer_assets` / `limited_reserve_transfer_assets` specifying such an ERC20 as the `Asset`) would then:
1. Lock less real collateral in `TransfersCheckingAccount` than the amount recorded in the XCM holding register / forwarded in `ReserveAssetDeposited`/`DepositReserveAsset` to a remote chain.
2. Allow a remote chain to mint/credit a derivative representation for the full nominal `amount`, while the actual ERC20 backing on Asset Hub is short by the fee — unbacked issuance of the derivative asset.
3. On the reverse leg (deposit/unlock), further "leakage" occurs when unlocking to a beneficiary, and once the checking account's true ERC20 balance dips below the sum of nominal amounts recorded across all in-flight/round-tripped transfers, later `deposit_asset_with_surplus` calls will either revert (`FailedToTransactAsset`, trapping assets) or, if the checking account happens to still hold enough balance from unrelated deposits, silently consume other users' collateral — the same "last redeemer can't withdraw" insolvency pattern described for Alice/Bob in the source report.

### Impact Explanation
This breaks the fundamental 1:1 backing assumption between locked ERC20 collateral and XCM-recorded/derivative-asset amounts, which can lead to unbacked issuance of a derivative asset on a destination chain/parachain and/or a stuck reserve that fails later legitimate withdrawals for unrelated users (fund lock / insolvency). Depending on exploitation pattern (repeated round trips with a crafted fee-on-transfer token, possibly amplified with high fee percentages), this could escalate from Medium (isolated user-token insolvency, matching the accepted severity of the original Taurus report) toward High if it is shown to allow systematically draining the checking account's genuine collateral to benefit an attacker at other users' expense.

### Likelihood Explanation
Likelihood is constrained by the fact that this only affects ERC20 tokens explicitly chosen by the *sender* of an XCM asset transfer (the attacker must use their own crafted fee-on-transfer contract as the `Asset`), and depends on whether `ERC20Matcher`/associated registration logic permits an arbitrary, unregistered pallet-revive contract address to be matched as a valid XCM fungible asset without any allow-listing. I was not able to fully inspect `ERC20Matcher`'s implementation within the available iterations (only its usage site was located, not its full source), so it is **uncertain** whether arbitrary unregistered ERC20 contracts are matchable, or whether some registration/allow-list step (e.g., only "registered" foreign assets are matched) mitigates the permissionless-deployment precondition. This uncertainty should be resolved before treating this as a confirmed, immediately exploitable issue.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the checking account's (or beneficiary's) ERC20 `balanceOf` immediately before and after the `transfer`/`transferFrom` call, and use the actual observed delta — not the nominal `amount` — when constructing `AssetsInHolding` credits or when considering a deposit "complete." If the actual delta is less than `amount`, either fail the XCM instruction (`FailedToTransactAsset`) or credit/report only the actual delta, so that the XCM holding register and any downstream reserve/derivative-asset minting always reflect real collateral movement rather than the requested nominal amount.

### Proof of Concept
No PoC was executed. This assessment is based on static analysis of `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs` and its wiring in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`. A full reproduction would require: (1) confirming `ERC20Matcher`'s asset-matching rules allow arbitrary unregistered pallet-revive contracts as XCM assets, (2) deploying a fee-on-transfer `IERC20` contract via pallet-revive, and (3) driving a `pallet_xcm::transfer_assets`/reserve-transfer round trip through the emulated Asset Hub Westend integration-test harness while asserting `TransfersCheckingAccount`'s real `balanceOf` diverges from the XCM-recorded/forwarded amount. This reproduction was not run; the finding should be treated as a plausible analog requiring targeted verification of `ERC20Matcher`, not a confirmed exploit.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L150-216)
```rust
	fn withdraw_asset_with_surplus(
		what: &Asset,
		who: &Location,
		_context: Option<&XcmContext>,
	) -> Result<(AssetsInHolding, Weight), XcmError> {
		tracing::trace!(
			target: "xcm::transactor::erc20::withdraw",
			?what, ?who,
		);
		let (asset_id, amount) = Matcher::matches_fungibles(what)?;
		let who = AccountIdConverter::convert_location(who)
			.ok_or(MatchError::AccountIdConversionFailed)?;
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
				} else {
					tracing::debug!(target: "xcm::transactor::erc20::withdraw", "contract transfer failed");
					Err(XcmError::FailedToTransactAsset("ERC20 contract transfer failed"))
				}
			}
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::withdraw", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err(XcmError::FailedToTransactAsset("ERC20 contract execution errored"))
		}
	}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L218-307)
```rust
	/// Deposits assets from holding to a beneficiary account via ERC20 transfer.
	///
	/// Note: This implementation only handles a single fungible asset at a time. The
	/// `AssetsInHolding` parameter is required by the `TransactAsset` trait, but callers
	/// should ensure only one asset is passed. If multiple assets are present, only the
	/// first fungible asset will be deposited and the rest will be silently ignored.
	/// The `defensive_assert!` helps catch misuse during development.
	fn deposit_asset_with_surplus(
		what: AssetsInHolding,
		who: &Location,
		_context: Option<&XcmContext>,
	) -> Result<Weight, (AssetsInHolding, XcmError)> {
		tracing::trace!(
			target: "xcm::transactor::erc20::deposit",
			?what, ?who,
		);
		defensive_assert!(what.len() == 1, "Trying to deposit more than one asset!");
		// Check we handle this asset.
		let maybe = what
			.fungible_assets_iter()
			.next()
			.and_then(|asset| Matcher::matches_fungibles(&asset).ok());
		let (asset_contract_id, amount) = match maybe {
			Some(inner) => inner,
			None => return Err((what, MatchError::AssetNotHandled.into())),
		};
		let who = match AccountIdConverter::convert_location(who) {
			Some(inner) => inner,
			None => return Err((what, MatchError::AccountIdConversionFailed.into())),
		};
		// We need to map the 32 byte beneficiary account to a 20 byte account.
		let eth_address = T::AddressMapper::to_address(&who);
		let address = Address::from(Into::<[u8; 20]>::into(eth_address));
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
		// We need to return this surplus for the executor to allow refunding it.
		let surplus = weight_limit.saturating_sub(weight_consumed);
		tracing::trace!(target: "xcm::transactor::erc20::deposit", ?weight_consumed, ?surplus, ?storage_deposit);
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
		} else {
			tracing::debug!(target: "xcm::transactor::erc20::deposit", ?result, "Error");
			// This error could've been duplicate smart contract, out of gas, etc.
			// If the issue is gas, there's nothing the user can change in the XCM
			// that will make this work since there's a hardcoded gas limit.
			Err((what, XcmError::FailedToTransactAsset("ERC20 contract execution errored")))
		}
	}
}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L221-246)
```rust
/// Transactor for ERC20 tokens.
pub type ERC20Transactor = assets_common::ERC20Transactor<
	// We need this for accessing pallet-revive.
	Runtime,
	// The matcher for smart contracts.
	assets_common::ERC20Matcher,
	// How to convert from a location to an account id.
	LocationToAccountId,
	// The maximum gas that can be used by a standard ERC20 transfer.
	ERC20TransferGasLimit,
	// The maximum storage deposit that can be used by a standard ERC20 transfer.
	ERC20TransferStorageDepositLimit,
	// We're generic over this so we can't escape specifying it.
	AccountId,
	// Checking account for ERC20 transfers.
	ERC20TransfersCheckingAccount,
>;

/// Means for transacting assets on this chain.
pub type AssetTransactors = (
	FungibleTransactor,
	FungiblesTransactor,
	ForeignFungiblesTransactor,
	UniquesTransactor,
	ERC20Transactor,
);
```
