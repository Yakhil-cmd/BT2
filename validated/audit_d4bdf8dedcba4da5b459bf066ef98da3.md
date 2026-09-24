### Title
`ERC20Transactor` credits/debits the XCM holding register by the requested amount instead of the amount actually moved by the ERC20 contract, breaking accounting for fee-on-transfer/deflationary/rebasing ERC20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, used by `pallet-xcm-executor` to move arbitrary `pallet-revive`-deployed ERC20 tokens in and out of a shared `TransfersCheckingAccount`, only inspect the boolean return value of `IERC20.transfer()`. They never compare the checking account's actual token balance before and after the call. For fee-on-transfer, deflationary or rebasing ERC20 tokens this causes the XCM holding register (and the checking account's real balance) to diverge from the amount the runtime believes was moved, exactly the missing-balance-check pattern described in the referenced SKALE `DepositBoxERC20` finding.

### Finding Description
`ERC20Transactor` is a `TransactAsset` implementation wired into the Asset Hub Westend XCM configuration (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) to let XCM programs withdraw/deposit ERC20 tokens deployed as `pallet-revive` smart contracts. [1](#0-0) 

In `withdraw_asset_with_surplus`, the transactor calls `IERC20::transferCall` to move `amount` tokens from the user `who` into `TransfersCheckingAccount`, and if the contract returns `true` it unconditionally mints an `Erc20Credit(amount)` into the XCM holding register: [2](#0-1) 

Similarly, `deposit_asset_with_surplus` calls `IERC20::transferCall` from `TransfersCheckingAccount` to the beneficiary for `amount`, and on a `true` return simply returns success without verifying the beneficiary (or the checking account) balance actually changed by `amount`: [3](#0-2) 

Neither function reads `IERC20.balanceOf(TransfersCheckingAccount)` (or the recipient) before and after the transfer to infer the actual amount moved; both trust the `amount` requested by the caller and the boolean success flag alone. `Matcher::matches_fungibles` only maps an asset location to an arbitrary `pallet-revive` contract address `asset_id` — it performs no allowlist restricting which ERC20 implementations may be used, so any deployed ERC20 contract satisfying the matcher can be transacted, including tokens with fee-on-transfer, deflationary burn-on-transfer, or rebasing supply mechanics. [4](#0-3) 

This is the direct FRAME/XCM analog of the SKALE `DepositBoxERC20` issue: a "vault" account (`TransfersCheckingAccount`) accepts an arbitrary, attacker-influenced ERC20 token and the surrounding accounting logic assumes `amount_requested == amount_actually_transferred`, without a before/after balance check.

### Impact Explanation
If a fee-on-transfer or deflationary ERC20 token is registered/matched by `Matcher` for use with this transactor:
- On withdraw, the checking account may receive less than `amount` (fee burned in transit), yet the XCM holding register is credited with the full `amount`. Later `deposit_asset_with_surplus` calls that debit this "phantom" surplus from the checking account will drain tokens that other users deposited, since the checking account's real balance is lower than the sum of credits recorded across concurrent XCM operations.
- On deposit, the beneficiary may receive less than `amount` while the executor treats the deposit as fully successful, causing downstream logic (refunds, multi-hop reserve transfers, or PNA representations that mint on the destination chain based on the reported `amount`) to over-credit relative to what was actually delivered.
- For rebasing tokens, the checking account's balance can silently increase or decrease between the withdraw and later deposit legs of unrelated XCM messages, meaning credited "amounts" in holding no longer correspond 1:1 to redeemable ERC20 balance, allowing accounting desync and potential draining of the shared checking account by users who deposit ordinary tokens and withdraw against the inflated/decoupled balance.

This is a shared-vault fund-loss / accounting-integrity issue reachable by any user who can construct an XCM program invoking this transactor with a token they control (deploy their own fee-on-transfer/rebasing ERC20 via `pallet-revive` and get it matched), classifying it as Medium severity, consistent with the original report's rating.

### Likelihood Explanation
Likelihood depends on whether `Matcher` (the `MatchesFungibles` implementation configured in `asset-hub-westend`'s `xcm_config.rs`) restricts eligible ERC20 contracts to a vetted allowlist versus accepting any `pallet-revive` contract address whose asset location resolves via the configured location-to-address mapping. The current code shows the transactor itself performs no allowlist or balance-invariant check; the actual severity depends on the concrete `Matcher`/`AssetIdConverter` configuration in `asset-hub-westend/src/xcm_config.rs`, which is wired in but whose full matching/allowlist logic was not directly inspected here (out of scope of the retrieved snippets). If the matcher permits permissionless registration of arbitrary ERC20 contracts (e.g., any pallet-revive contract implementing the `IERC20` ABI), the likelihood is High; if only a governance-curated set of ERC20 contracts can ever be matched, likelihood is Low. This constrains confidence to Medium overall.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read `IERC20.balanceOf` on the relevant account (checking account for withdraw, beneficiary for deposit) immediately before and after the `transfer` call, and use the observed balance delta — not the requested `amount` — as the amount credited to holding / considered successfully deposited. Alternatively, restrict `Matcher`/the ERC20 allowlist to tokens verified not to implement fee-on-transfer, rebasing, or deflationary supply mechanics before they can be transacted through the shared `TransfersCheckingAccount`.

### Proof of Concept
No executable PoC was run; this analysis is based on static code inspection of `ERC20Transactor` in `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`, confirmed to be wired into the live Asset Hub Westend runtime XCM configuration (`cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs`) and exercised by tests in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs` (both files reference `TransfersCheckingAccount`/`ERC20Transactor`). Full reachability details (concrete `Matcher` allowlist behavior, and whether externally-deployed arbitrary ERC20 contracts can be matched) were not verified beyond the searched snippets due to index scope limits; a background Devin session with full repository access would be needed to confirm the exact `Matcher` configuration and construct a concrete integration-test reproduction (deploying a mock fee-on-transfer ERC20 via `pallet-revive`, executing an XCM program through `ERC20Transactor`, and asserting the checking-account balance divergence from the credited holding amount). [5](#0-4)

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-298)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L1-1)
```rust
// Copyright (C) Parity Technologies (UK) Ltd.
```
