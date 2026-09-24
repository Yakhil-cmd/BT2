### Title
ERC20Transactor mints XCM holding credit for the full nominal amount while fee-on-transfer ERC20 tokens deliver less to the checking account, causing unbacked asset credit / stuck deposits - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor`, the XCM `TransactAsset` implementation used to let `pallet-revive` ERC20 contracts participate in XCM reserve transfers, credits the XCM holding register with the exact `amount` requested by the message, without verifying that the underlying ERC20 `transfer` call actually moved that amount into the `TransfersCheckingAccount`. This is the same root cause as the reported bug: for ERC20 tokens that charge a fee-on-transfer (e.g., USDT-style tokens), the contract-reported "success" return value does not guarantee the recipient received the full nominal `amount`.

### Finding Description
`withdraw_asset_with_surplus` performs an ERC20 `transfer(checking_address, amount)` call from the user's account to `TransfersCheckingAccount`, and on success unconditionally constructs XCM holding credit for the full `amount`: [1](#0-0) 

It never re-reads the checking account's actual ERC20 balance delta; it trusts the boolean `transferCall` return value and mints an `Erc20Credit(amount)` imbalance regardless of what the token contract truly moved. Because the checking account is shared across all XCM ERC20 transfers, any fee/deflationary ERC20 configured as an XCM asset will cause the pallet's internal bookkeeping (`Erc20Credit` amounts flowing through `AssetsInHolding`) to diverge from the checking account's real on-chain balance.

Symmetrically, `deposit_asset_with_surplus` transfers the full held `amount` (as extracted from `AssetsInHolding`) out of the checking account to the beneficiary via another ERC20 `transfer` call: [2](#0-1) 

If the token also charges a fee on this second transfer, the beneficiary receives less than `amount`, while the runtime treats the deposit as fully successful (`Ok(surplus)`), permanently losing the fee amount from anyone's accounted balance — this portion is unrecoverably "leaked" from the checking account's real balance versus the nominal amount XCM believes was deposited.

The compounding effect across many withdraw/deposit cycles on a fee-on-transfer ERC20 is that the checking account's real balance progressively falls below the sum of nominal credits the runtime has issued via `Erc20Credit`, because every `withdraw_asset` under-collects by the fee and every `deposit_asset` over-pays relative to what the checking account actually has versus what is nominally owed.

This mirrors exactly the reported bug class: "actual transferred amount may differ from expected" for fee-on-transfer tokens, where a contract wraps a `transfer` call and assumes `actual == requested`.

### Impact Explanation
If the checking account's tracked balance falls behind due to compounding fee losses, subsequent legitimate `deposit_asset` calls for other users' ERC20 XCM transfers can begin failing (the ERC20 `transferCall` will return `false` or revert due to insufficient balance in the checking account), causing denial of service for further genuine users' asset deposits on that ERC20. In the more severe direction, whether an attacker can extract more value than they put in (effectively draining the checking account faster than their own contribution) depends on whether withdraw-side fees are lower than deposit-side fees for the specific token configured, but at minimum this breaks the fungibility/backing invariant that the XCM holding register is supposed to represent an exact 1:1 claim on the checking account's real ERC20 balance.

### Likelihood Explanation
This requires that a fee-on-transfer / deflationary ERC20 contract deployed via `pallet-revive` is configured as an XCM-transactable asset kind matched by `Matcher: MatchesFungibles` for `ERC20Transactor`, which is wired into `asset-hub-westend`'s XCM configuration. Since `pallet-revive` allows any signed user to deploy arbitrary EVM-compatible contracts (no privileged role needed), and asset registration for ERC20-as-XCM-asset appears governed by the `Matcher`/asset registry configuration (not verified in full here — I did not trace the exact governance/permission gate that allows a specific ERC20 contract address to become a recognized XCM asset kind, e.g. whether that requires a privileged `ForeignAssets`-style registration or is fully permissionless). This uncertainty affects whether the likelihood is "any user can trigger this" versus "requires an asset registrar to first opt the ERC20 in."

### Recommendation
In `withdraw_asset_with_surplus`, read the checking account's ERC20 balance before and after the `transfer` call (or use `transferFrom`/balance-diffing) and credit `AssetsInHolding` with the *actual* balance delta rather than the nominal `amount`. Symmetrically, in `deposit_asset_with_surplus`, verify the beneficiary's actual balance increase matches expectations, and if a discrepancy (fee) is detected, either fail the transfer, adjust the imbalance accounting to reflect the shortfall, or reject configuring fee-on-transfer tokens as XCM-transactable assets in the `Matcher` configuration.

### Proof of Concept
No executable PoC was run against a live/public network, consistent with the constraints of this exercise. The analysis is based on static code inspection of the guarded methods:
- `ERC20Transactor::withdraw_asset_with_surplus` at [3](#0-2) , which fails to check actual vs nominal amount transferred before minting `Erc20Credit(amount)`.
- `ERC20Transactor::deposit_asset_with_surplus` at [4](#0-3) , which pays out the full nominal amount without verifying delivery.
- Confirmed live wiring (not test-only) via `cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs` referencing `ERC20Transactor`, and `cumulus/parachains/runtimes/assets/common/src/lib.rs` re-exporting it.

I was not able to fully confirm within the available iterations (a) the exact permission model for registering an arbitrary `pallet-revive` ERC20 contract as a matched XCM asset kind (whether permissionless or gated by an asset registrar), and (b) whether a live Parity bug-bounty program explicitly covers `asset-hub-westend`'s `erc20_transactor.rs` module. These should be verified with a Devin session that can execute an integration test (e.g., using `pallet-revive`'s fixture ERC20 contracts with a custom fee-charging `transfer` override) to concretely demonstrate the checking-account balance divergence end-to-end.

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L225-306)
```rust
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
