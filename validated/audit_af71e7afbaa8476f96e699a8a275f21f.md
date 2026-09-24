### Title
ERC20 asset transactor credits/moves the nominal XCM amount without verifying the actual token amount transferred by the ERC-20 contract - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `ERC20Transactor::deposit_asset_with_surplus` treat an ERC20 `transfer()` call as fully successful for the *nominal* `amount` requested as soon as the ABI-decoded boolean return value is `true`, without ever comparing the account/checking-account balance before and after the call. This mirrors the OpenQ finding exactly: the amount actually received by the destination account is never checked against the amount assumed to have moved.

### Finding Description
`ERC20Transactor` is registered as one of the production `AssetTransactors` on Asset Hub Westend [1](#0-0) , and it is reachable through the permissionless, signed `PolkadotXcm::execute` extrinsic, as demonstrated by the existing test that submits an XCM `WithdrawAsset`/`DepositAsset` program against an attacker-deployed contract [2](#0-1) . The matcher maps any `AccountKey20 { key }` location directly to the smart-contract address `key` [3](#0-2) , and contract deployment via `pallet-revive` is itself permissionless — so an attacker can deploy an arbitrary contract implementing `IERC20` semantics and immediately reference it by address in an XCM program with no whitelisting/registration step.

In `withdraw_asset_with_surplus`, the code calls `transferCall` on the attacker-supplied contract for the requested `amount`, and if the decoded return value is `true`, it unconditionally creates an `AssetsInHolding` credit equal to the full requested `amount`: [4](#0-3) 

Symmetrically, `deposit_asset_with_surplus` calls `transfer()` from the checking account to the beneficiary for `amount`, and treats a `true` return as full success without checking that the beneficiary's balance actually increased by `amount`: [5](#0-4) 

Nothing in either path calls `balanceOf` before/after, or otherwise reconciles the ERC20 contract's real balance delta with the `amount` value baked into the XCM `AssetsInHolding` credit (`Erc20Credit(amount)` at line 200). Any ERC20-like contract that implements a deflationary/fee-on-transfer `transfer()` (or one that simply returns `true` while moving fewer/zero tokens) will desynchronize the XCM-level accounting (the nominal `amount` believed to be in `holding`/at the destination) from the actual token balance moved on-chain — exactly the "volume received should not be 0 / should match requested" violation described in the report, transplanted from the Solidity `receiveFunds` pattern to the FRAME/XCM `TransactAsset::withdraw_asset`/`deposit_asset` pattern.

### Impact Explanation
Because the contract is entirely attacker-controlled, in isolation this only lets the attacker create phantom holding value for their own token, which by itself doesn't steal funds. The severity becomes concerning only if such a token is later used against real backing (e.g., paired in an `AssetConversion` pool, bridged to represent value cross-chain, or accepted by another party as payment) — in those compositions the accounting mismatch (nominal `amount` vs. actual balance movement) could propagate an inflated/unbacked value assumption downstream. I was not able to fully trace or demonstrate a concrete cross-pallet loss scenario (e.g., into `pallet-asset-conversion` or a bridge leg) within the available exploration; this would need a dedicated PoC building a fee-on-transfer contract, wiring it through `PolkadotXcm::execute`, and observing the resulting `AssetsInHolding`/beneficiary balance divergence, plus tracing whether any consuming pallet trusts that nominal value.

### Likelihood Explanation
High reachability: contract deployment through `pallet-revive` and XCM program submission through `PolkadotXcm::execute` are both ordinary, permissionless, signed operations with no privileged prerequisite. The `ERC20Transactor` is live/wired in the Asset Hub Westend runtime today (not test/mock-only), unlike the `#![cfg(...)]`-gated `impl_fungibles.rs` variant, which is explicitly test-only and out of scope.

### Recommendation
In `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read the relevant account's `balanceOf` (or an equivalent authoritative measure) immediately before and after the `transfer()` call, compute the actual delta, and use that delta — not the requested `amount` — both for the `Erc20Credit` placed into `AssetsInHolding` and for any success/failure determination. If the delta is `0`, the call should be treated as failed regardless of the boolean return value, analogous to the OpenQ fix's `require(volumeReceived > 0)`.

### Proof of Concept
Not executed. A full PoC would require: (1) compiling/deploying a custom `IERC20`-compatible contract via `pallet-revive` whose `transfer()` always returns `true` but transfers `0`/reduced tokens (a "fake fee-on-transfer" token, similar in spirit to the existing `smart_contract_does_not_return_bool_fails` test harness at `cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs:2026-2081`), (2) submitting a `PolkadotXcm::execute` program performing `WithdrawAsset`/`DepositAsset` referencing that contract by `AccountKey20`, and (3) asserting that the resulting `AssetsInHolding` credit / beneficiary ERC20 balance does not match the actual on-chain balance delta of the checking account or beneficiary. This reproduction was not run in this session; the guard is proven missing purely via static code reading of `erc20_transactor.rs`, so I cannot assert an "actual vs. expected" runtime result, only that the missing-check pattern exists and is reachable through legitimate, permissionless entry points.

### Citations

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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2054-2079)
```rust
		let Contract { addr: non_erc20_address, .. } = bare_instantiate(&sender, code)
			.transaction_limits(TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::from_parts(500_000_000_000, 10 * 1024 * 1024),
				deposit_limit: Balance::MAX,
			})
			.data(constructor_data)
			.build_and_unwrap_contract();

		let wnd_amount_for_fees = 1_000_000_000_000u128;
		let erc20_transfer_amount = 100u128;
		let message = Xcm::<RuntimeCall>::builder()
			.withdraw_asset((Parent, wnd_amount_for_fees))
			.pay_fees((Parent, wnd_amount_for_fees))
			.withdraw_asset((
				AccountKey20 { key: non_erc20_address.into(), network: None },
				erc20_transfer_amount,
			))
			.deposit_asset(AllCounted(1), beneficiary.clone())
			.build();
		// Execution fails but doesn't panic.
		assert!(PolkadotXcm::execute(
			RuntimeOrigin::signed(sender.clone()),
			Box::new(VersionedXcm::V5(message)),
			Weight::from_parts(2_500_000_000, 220_000),
		)
		.is_err());
```

**File:** prdoc/stable2506/pr_7762.prdoc (L6-15)
```text
doc:
  - audience: Runtime Dev
    description: |
      This PR introduces an Asset Transactor for dealing with ERC20 tokens and adds it to Asset Hub
      Westend.
      This means asset ids of the form `{ parents: 0, interior: X1(AccountKey20 { key, network }) }` will be
      matched by this transactor and the corresponding `transfer` function will be called in the
      smart contract whose address is `key`.
      If your chain uses `pallet-revive`, you can support ERC20s as well by adding the transactor, which lives
      in `assets-common`.
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-203)
```rust
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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L253-298)
```rust
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
