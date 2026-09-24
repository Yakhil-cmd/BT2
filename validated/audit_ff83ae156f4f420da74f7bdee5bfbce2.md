### Title
ERC20Transactor `withdraw_asset`/`deposit_asset` trust the ERC20 `transfer` boolean return value instead of verifying actual balance delta, allowing unbacked XCM asset credit - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` execute a Solidity `transfer(to, value)` call against an arbitrary, permissionlessly-deployable `pallet-revive` contract, and treat the call as fully successful purely because it did not revert and ABI-decoded a `true` return value. This is exactly the MonoX bug class: minting/crediting an internal accounting unit (here, an `AssetsInHolding` XCM credit of `amount`) based on a claimed/declared transfer outcome, without checking that the token balance of the `TransfersCheckingAccount` actually changed by `amount`.

### Finding Description
In `withdraw_asset_with_surplus` [1](#0-0) , the transactor calls the user-supplied contract's `transfer` function to move `amount` tokens to `ERC20TransfersCheckingAccount`, and if the call does not revert and decodes to `true`, it unconditionally constructs `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` [2](#0-1) . `Erc20Credit` is explicitly documented as *not* enforcing runtime-level balance constraints - it just tracks a number that the XCM executor trusts: [3](#0-2) .

Since any user can permissionlessly deploy an arbitrary Solidity contract to `pallet-revive` (this transactor is wired into `AssetHubWestend`'s `AssetTransactors` via `ERC20Transactor` [4](#0-3) , and matched purely by the contract's `H160` address via `ERC20Matcher`), an attacker can deploy a MonoX-style `EvilERC20` whose `transfer(to, value)` function ignores the requested `value`, always transfers `0` (or some fixed dust amount) to `to`, and always returns `true`. When this contract is referenced from an XCM program (e.g., `withdraw_asset((AccountKey20 { key: evil_addr }, huge_amount))`), the transactor will:
1. Call `transfer(checking_account, huge_amount)` on the attacker's contract.
2. The contract returns `true` without moving `huge_amount` (or moves far less/none) into the checking account.
3. The code checks only `did_revert()` and the boolean ABI-decoded return - never the checking account's actual token balance before/after.
4. It credits the XCM holding register with `Erc20Credit(huge_amount)`, i.e., `amount` units of value with zero real backing in the checking account.

The symmetric bug exists in `deposit_asset_with_surplus` [5](#0-4) , which similarly trusts the return value when moving tokens from the checking account to a beneficiary, without verifying the checking account balance actually decreased or the beneficiary balance actually increased by `amount`.

This holding credit, unbacked by real contract balance, can then be routed anywhere a normal XCM asset would go within the same `execute`/`Transact` program - e.g., deposited to a victim account, used to `BuyExecution`, or (subject to reachability of other legs of the message) forwarded further - creating value from nothing, the direct analog of MonoX's "declared amount ≠ actually transferred amount" unrestricted minting.

### Impact Explanation
An attacker with no privileged role can deploy a standard-looking ERC20 contract and use it to make the XCM executor believe an arbitrary amount of "backed" value was withdrawn/deposited, when the underlying contract balance moved by a different (possibly zero) amount. Because the holding-register credit is fungible and treated identically to genuine asset credits by the rest of the XCM executor (fee payment, deposit_asset, etc.), this can be used to fabricate value for local execution (e.g., self-crediting an account, paying for weight/fees with fabricated funds) inside a single `pallet_xcm::execute` call. The severity depends on what other legs of the message can consume this holding (e.g., depositing to accounts, buying execution) - since the credit is indistinguishable from a real one to the rest of the executor, this is a High-severity integrity break (unbacked issuance within the XCM asset-holding accounting), matching the "Score: Impact 4 / Likelihood 4" MonoX classification for the analogous root cause.

### Likelihood Explanation
High. No privileged role or governance action is required: deploying a contract via `pallet-revive` and executing `pallet_xcm::execute` with a `WithdrawAsset`/`DepositAsset` referencing that contract's address are both standard, permissionless, signed-extrinsic operations. The vulnerable code path is reached unconditionally whenever an `AccountKey20`-addressed asset is used in an XCM program that includes the `ERC20Transactor` in the runtime's `AssetTransactors` tuple, as is the case for `asset-hub-westend`.

### Recommendation
Apply the same fix MonoX applied: measure the actual balance delta of the `TransfersCheckingAccount` (and beneficiary) before and after the `transfer` call, and use that measured delta - not the declared `amount` or the boolean return value - as the amount credited into `AssetsInHolding` (or debited on deposit). Concretely: 
1. In `withdraw_asset_with_surplus`, call `balanceOf(checking_address)` before and after the `transfer` call and construct `Erc20Credit(actual_delta)` instead of `Erc20Credit(amount)`.
2. In `deposit_asset_with_surplus`, similarly verify the beneficiary/checking account balance actually changed by `amount` before treating the deposit as fully successful; otherwise return the unconsumed remainder as an error/partial result.
3. Treat any mismatch between requested and observed delta as a hard failure (`FailedToTransactAsset`) rather than silently trusting the return value.

### Proof of Concept
Not executed - no terminal/build access is available in this session to compile a malicious `resolc`/Solidity ERC20 fixture, deploy it via `pallet_revive::Pallet::bare_instantiate`, and run a `pallet_xcm::execute` extrinsic to observe the fabricated `AssetsInHolding` credit. The existing test `withdraw_and_deposit_erc20s` in `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs:1871-1936` demonstrates the legitimate code path and provides a ready harness (compiling a fixture with `compile_module_with_type`, `bare_instantiate`, and `PolkadotXcm::execute`) that a reproduction would need to adapt with a malicious `transfer` implementation returning `true` while moving less than the requested `value`, then asserting the beneficiary/checking-account `Revive`-tracked balance versus the credited `AssetsInHolding` amount diverge. This is flagged as an unconfirmed, code-reachability-based finding pending actual execution.

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L73-89)
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
```

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L225-298)
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
