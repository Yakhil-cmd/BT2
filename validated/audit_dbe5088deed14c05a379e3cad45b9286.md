### Title
`ERC20Transactor` credits the full requested amount into the XCM holding register even when the underlying ERC20 `transfer` call actually delivers less (fee-on-transfer / non-standard tokens) - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` invoke the target ERC20 contract's `transfer()` via `pallet_revive::Pallet::<T>::bare_call` and, upon seeing a `true` boolean return value, unconditionally treat the *requested* `amount` as having moved in full. This is the same root-cause pattern as the reported Teller `CollateralEscrowV1` bug: the code trusts the nominal transfer amount instead of verifying the actual balance delta, which breaks down for fee-on-transfer / deflationary ERC20 tokens deployed as `pallet-revive` contracts and referenced by an asset-hub's XCM configuration.

### Finding Description
`ERC20Transactor` is a `TransactAsset` implementation used by asset-hub runtimes (wired in `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) to let XCM programs move ERC20 tokens deployed via `pallet-revive` in and out of the XCM holding register.

- `withdraw_asset_with_surplus` (`erc20_transactor.rs:150-216`) calls `IERC20::transferCall{ to: checking_address, value: amount }` from the user to a fixed `TransfersCheckingAccount`. If the call succeeds and decodes to `true`, it creates `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` — crediting the *full requested* `amount` into the XCM holding register: [1](#0-0) 

- `deposit_asset_with_surplus` (`erc20_transactor.rs:225-306`) does the symmetric operation: it reads `amount` back out of the XCM holding (`Matcher::matches_fungibles`) and calls `IERC20::transferCall{ to: beneficiary, value: amount }` from the `TransfersCheckingAccount`, again treating a `true` boolean return as proof that the full `amount` was delivered: [2](#0-1) 

The `Erc20Credit` imbalance type used to represent this value inside the holding register performs no independent balance check against the checking account's actual token balance — it is a pure counter: [3](#0-2) 

If the ERC20 contract implements a fee-on-transfer (or otherwise non-standard "transfer moves less than `value`") behavior — which is entirely possible since any `pallet-revive` contract address can be registered as a foreign/ERC20 asset for XCM purposes via the asset-hub's `Matcher`/`ConvertAssetId` configuration — then:
1. On withdraw, the checking account actually receives `amount - fee`, but the XCM holding register is credited with the full `amount`.
2. Any subsequent XCM instruction in the same program (e.g. `DepositAsset`, `InitiateTransfer` to another chain, `BuyExecution`) operates on the inflated holding value of `amount`, not the real `amount - fee` that the checking account holds.
3. When `deposit_asset_with_surplus` later tries to pay out the inflated `amount` to a beneficiary, the checking account does not actually have enough ERC20 balance; the underlying `transfer()` call will either revert (return `false`/revert), in which case `what` is returned unconsumed and the assets are trapped in the executor (`AssetsTrapped`, i.e., stuck/lost funds analogous to "stuck in escrow"), or — if the same fee-on-transfer token is used cross-chain and a *different*, non-fee-charging leg is used to represent the credited amount elsewhere (e.g. mint on a different chain via `InitiateTransfer`/reserve semantics) — it can create an accounting mismatch between what is actually custodied in the checking account and what has been credited/forwarded, i.e., unbacked issuance of the XCM-side representation of the token.

This mirrors exactly the violated invariant in the Teller report: the code assumes `actual_amount_moved == requested_amount`, which is false for fee-on-transfer tokens, and the checking/escrow account ends up holding less than what the accounting layer believes, leading to trapped/stuck funds or accounting divergence.

### Impact Explanation
This is not a theoretical EVM-only concern forced onto FRAME: `ERC20Transactor` is real, production Cumulus/asset-hub code that bridges `pallet-revive` ERC20 contracts into the XCM asset model, and it is actively wired into `asset-hub-westend`'s `xcm_config.rs`. Because the credited/withdrawn amount in the XCM holding register is decoupled from the real token balance delta at the checking account, a token that is fee-on-transfer (deployable by any user as an ERC20 contract under `pallet-revive`, then registered as a foreign asset) can cause:
- Assets trapped in the checking account / XCM holding register (denial of withdrawal, funds effectively "stuck," directly analogous to the reported issue), and/or
- Divergence between the holding register's belief about available balance and the checking account's real ERC20 balance, which can be leveraged in multi-hop XCM programs that use the (inflated) holding amount for further deposits/transfers before the shortfall is discovered.

The severity depends on whether a downstream code path exists that lets an attacker deposit/forward the inflated holding value to a destination that does not itself re-verify against the checking account's real balance (e.g., a further reserve-based mint on another chain). This deeper reachability (whether inflated credits can be forwarded off-chain before the checking-account shortfall is discovered) could not be fully confirmed from the available index; it would require tracing the exact `xcm_config.rs` `AssetTransactors` ordering and the full XCM program semantics for multi-asset/multi-hop transfers involving ERC20-backed assets, which is beyond what the indexed code snippets show.

### Likelihood Explanation
Likelihood requires: (a) a `pallet-revive` ERC20 contract with fee-on-transfer semantics being deployed by an attacker (fully within a normal, unprivileged user's capability — deploying and registering an ERC20 contract does not require governance or privileged origin), and (b) that contract being registered/matched by `Matcher`/`ConvertAssetId` as an XCM-recognized ERC20 asset on the asset-hub. Whether unprivileged registration of arbitrary ERC20 contracts as XCM-matched assets is permitted (vs. requiring governance-controlled registration) was not fully confirmed from the indexed code — `Matcher: MatchesFungibles<H160, u128>` is generic and its concrete configuration in `asset-hub-westend`'s `xcm_config.rs` would need to be inspected directly to determine whether asset registration is permissionless or governance-gated. This materially affects likelihood and could not be verified with full confidence from the available index.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, do not assume the transferred amount equals the requested `amount` based solely on the boolean return value of `transfer()`. Instead, read the checking account's (or beneficiary's) ERC20 `balanceOf` before and after the `bare_call`, and credit/report only the actual balance delta into the `Erc20Credit`/holding register, returning an error (or a partial-transfer-aware result) if the delta is less than requested — consistent with how native FRAME token traits (e.g. `fungible::Mutate::transfer`, `fungibles::Mutate::transfer`) already return the *actual* amount moved rather than assuming success implies the full nominal amount was moved (see `substrate/frame/support/src/traits/tokens/fungibles/regular.rs`).

### Proof of Concept
No executable PoC was produced. Confirming actual exploitability would require: (1) verifying whether `Matcher`/asset registration in `asset-hub-westend`'s `xcm_config.rs` allows an unprivileged user to register an arbitrary `pallet-revive` ERC20 contract as an XCM-recognized fungible asset, and (2) constructing a `pallet-revive` fixture contract with fee-on-transfer `transfer()` semantics, then driving an XCM program (e.g. via `pallet_xcm::execute` similar to the existing `withdraw_and_deposit_erc20s` test in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs`) that withdraws from a user, observes the checking account's real ERC20 balance vs. the XCM holding register's credited amount, and attempts a subsequent deposit to demonstrate trapped assets or accounting mismatch. This reproduction was not executed against the codebase in this session; the finding is based on static code analysis of the transactor's balance-accounting logic ( [4](#0-3) ) and its wiring into `asset-hub-westend`'s XCM configuration.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L73-107)
```rust
/// A minimal imbalance tracking type that holds an ERC20 token amount.
///
/// This type implements the necessary imbalance accounting traits but does not perform
/// runtime-level balance enforcement. It's used to track ERC20 token amounts within XCM
/// asset holdings, where the actual balance constraints are enforced by the ERC20 smart
/// contract itself rather than the runtime.
struct Erc20Credit(u128);
impl UnsafeConstructorDestructor<u128> for Erc20Credit {
	fn unsafe_clone(&self) -> Box<dyn ImbalanceAccounting<u128>> {
		Box::new(Erc20Credit(self.0))
	}
	fn forget_imbalance(&mut self) -> u128 {
		let amount = self.0;
		self.0 = 0;
		amount
	}
}

impl UnsafeManualAccounting<u128> for Erc20Credit {
	fn saturating_subsume(&mut self, mut other: Box<dyn ImbalanceAccounting<u128>>) {
		let amount = other.forget_imbalance();
		self.0 = self.0.saturating_add(amount);
	}
}

impl ImbalanceAccounting<u128> for Erc20Credit {
	fn amount(&self) -> u128 {
		self.0
	}
	fn saturating_take(&mut self, amount: u128) -> Box<dyn ImbalanceAccounting<u128>> {
		let new = self.0.min(amount);
		self.0 = self.0 - new;
		Box::new(Erc20Credit(new))
	}
}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L150-306)
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
```
