## Analysis

The Teller report's root cause: **recording a *nominal* transferred amount into internal accounting instead of measuring the actual balance received**, followed by using that nominal (now-wrong) recorded amount for a second leg (repayment/withdrawal) that reverts because the actual token balance is short.

I found a structurally identical pattern in the Polkadot SDK's XCM `ERC20Transactor`, which lets XCM programs move Solidity ERC-20 tokens (deployed via `pallet-revive`) using `WithdrawAsset`/`DepositAsset`, wired into `AssetHubWestend`'s `AssetTransactors`. [1](#0-0) 

### Title
XCM `ERC20Transactor` credits/deposits the requested amount instead of the actually-received balance, breaking asset-conservation for fee-on-transfer ERC-20 tokens - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` transact Solidity ERC-20 tokens hosted on `pallet-revive` from/to XCM's holding register. Both functions trust the ERC-20 contract's `transfer` boolean return value as proof that exactly `amount` moved, and never compare the checking account's balance before/after the call. For a fee-on-transfer ERC-20 (a real-world, common token pattern, e.g. USDT-style deflationary/tax tokens), the checking account receives less than `amount` on withdraw, yet the transactor still credits `AssetsInHolding` with the full nominal `amount`. This is exactly the "recorded amount vs. actual received amount" mismatch identified in the Teller report.

### Finding Description
`withdraw_asset_with_surplus` calls the ERC-20 contract's `transfer(checking_account, amount)`: [2](#0-1) 

If the call succeeds and returns `true`, the code unconditionally creates `Erc20Credit(amount)` — the *requested* `amount`, not the checking account's actual balance delta: [3](#0-2) 

`deposit_asset_with_surplus` then unconditionally attempts `transfer(beneficiary, amount)` **from** the checking account, again using the nominal recorded `amount`, with no balance check beforehand: [4](#0-3) 

For a standard, well-behaved ERC-20 the invariant `withdrawn == deposited` holds and the shared `TransfersCheckingAccount` nets to zero across a message. For a fee-on-transfer token:
- On withdraw: sender's balance decreases by the full `amount`, but the checking account receives `amount - fee`. The transactor still records `amount` in `AssetsInHolding`.
- On deposit: the transactor tries to move the full (inflated) `amount` out of the checking account, which now holds less than that. Depending on the contract's own semantics this either (a) reverts/returns `false`, causing `XcmError::FailedToTransactAsset` and rolling back the whole extrinsic (the "repayment blocked" analog — funds effectively get stuck mid-transfer for a token that legitimately imposes a transfer fee), or (b) succeeds while under-delivering to the beneficiary, silently breaking the "amount you send is what you receive" invariant that the rest of the XCM program (refund_surplus, `DepositAsset { assets: AllCounted(..) }`, downstream hops) relies on.

Neither function reads `balanceOf(checking_account)` before and after the transfer to compute the actual delta — the exact fix Sherlock's original report recommended for `CollateralEscrowV1`.

### Impact Explanation
Any legitimate, unprivileged holder of a fee-on-transfer ERC-20 token deployed under `pallet-revive` (a real and permitted token pattern — deployment only requires `UploadOrigin = EnsureSigned<AccountId>`) who moves that asset through `pallet_xcm::execute`/`send` using this transactor can have their transfer either revert mid-flight (denial of service on their own funds routed through the shared checking account) or have the beneficiary silently receive less than the nominal amount while the rest of the XCM program's accounting (weight/asset refunds, `AllCounted` checks) believes the full amount moved. This is a Medium-severity integrity/availability issue matching the bounty's accepted class (blocked repayment/asset movement due to unaccounted fee-on-transfer deduction), not a theft of other users' funds, since ERC-20 balances are isolated per contract and the shared checking account only nets per-token.

### Likelihood Explanation
Reachable by any signed, unprivileged account: deploy an ERC-20 contract via `pallet_revive::instantiate` (`UploadOrigin = EnsureSigned`), then invoke `pallet_xcm::execute` (or a reserve-transfer XCM) referencing that contract's `AccountKey20` location, which is matched by `assets_common::ERC20Matcher` and routed to `ERC20Transactor`. No governance, no privileged role, no forged inherent is required — only a token contract with standard (if unusual) fee-on-transfer semantics, which is a common real-world token category the runtime advertises support for via the new ERC20 XCM integration.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, read `balanceOf` of the relevant account (checking account or beneficiary) immediately before and after the `transfer` call, and use `after - before` as the amount credited/recorded into `AssetsInHolding`/`Erc20Credit`, instead of trusting the nominal `amount` combined with the boolean return value. If the actual delta is less than requested, either fail the operation deterministically or adjust the credited surplus accordingly.

### Proof of Concept
I did not have terminal/sandbox access to compile and execute a live Rust/Solidity integration test in this session, so no test was run and no execution results can be claimed. A concrete reproduction would:
1. Deploy a Solidity ERC-20 (via `compile_module_with_type`/`bare_instantiate`, following the pattern in the existing `withdraw_and_deposit_erc20s` test) whose `transfer` deducts an extra fee whenever `to == checking_address` (or generally, a standard deflationary-token `transfer`). [5](#0-4) 

2. Fund the sender with this token, then execute an XCM program via `PolkadotXcm::execute` containing `WithdrawAsset`/`DepositAsset` for this token address (as in the existing `withdraw_and_deposit_erc20s`/`smart_contract_does_not_return_bool_fails` tests), and assert that either the beneficiary's `balanceOf` ends up strictly less than the requested transfer amount while the XCM execution reports `Outcome::Complete`, or that the deposit leg reverts with `FailedToTransactAsset` due to the checking account being short of the nominal recorded amount — both of which existing repo test scaffolding (`ExtBuilder`, `bare_instantiate`, `PolkadotXcm::execute`) is directly set up to exercise. [6](#0-5)

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L166-204)
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
				} else {
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-279)
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L1871-1935)
```rust
#[test]
fn withdraw_and_deposit_erc20s() {
	let sender: AccountId = ALICE.into();
	let beneficiary: AccountId = BOB.into();
	let revive_account = pallet_revive::Pallet::<Runtime>::account_id();
	let checking_account =
		asset_hub_westend_runtime::xcm_config::ERC20TransfersCheckingAccount::get();
	let initial_wnd_amount = 100_000_000_000_000_000u128;
	sp_tracing::init_for_tests();

	ExtBuilder::<Runtime>::default().build().execute_with(|| {
		// Bring the revive account to life.
		assert_ok!(Balances::mint_into(&revive_account, initial_wnd_amount));
		// Fund all accounts involved.
		assert_ok!(Balances::mint_into(&sender, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&beneficiary, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&checking_account, initial_wnd_amount));

		let code = compile_module_with_type("MyToken", FixtureType::Resolc)
			.expect("compile ERC20")
			.0;

		let initial_amount_u256 = U256::from(1_000_000_000_000u128);
		let constructor_data = sol_data::Uint::<256>::abi_encode(&initial_amount_u256);
		let Contract { addr: erc20_address, .. } = bare_instantiate(&sender, code)
			.transaction_limits(TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::from_parts(500_000_000_000, 10 * 1024 * 1024),
				deposit_limit: Balance::MAX,
			})
			.data(constructor_data)
			.build_and_unwrap_contract();

		let sender_balance_before = <Balances as fungible::Inspect<_>>::balance(&sender);

		let erc20_transfer_amount = 100u128;
		let wnd_amount_for_fees = 10_000_000_000_000u128;
		// Actual XCM to execute locally.
		let message = Xcm::<RuntimeCall>::builder()
			.withdraw_asset((Parent, wnd_amount_for_fees))
			.pay_fees((Parent, wnd_amount_for_fees))
			.withdraw_asset((
				AccountKey20 { key: erc20_address.into(), network: None },
				erc20_transfer_amount,
			))
			.deposit_asset(AllCounted(1), beneficiary.clone())
			.refund_surplus()
			.deposit_asset(AllCounted(1), sender.clone())
			.build();
		assert_ok!(PolkadotXcm::execute(
			RuntimeOrigin::signed(sender.clone()),
			Box::new(VersionedXcm::V5(message)),
			Weight::from_parts(600_000_000_000, 15 * 1024 * 1024),
		));

		// Revive is not taking any fees.
		let sender_balance_after = <Balances as fungible::Inspect<_>>::balance(&sender);
		// Balance after is larger than the difference between balance before and transferred
		// amount because of the refund.
		assert!(sender_balance_after > sender_balance_before - wnd_amount_for_fees);

		// Beneficiary receives the ERC20.
		let beneficiary_amount =
			<Revive as fungibles::Inspect<_>>::balance(erc20_address, &beneficiary);
		assert_eq!(beneficiary_amount, erc20_transfer_amount);
	});
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2026-2081)
```rust
// Here the contract returns a number but because it can be cast to true
// it still succeeds.
#[test]
fn smart_contract_does_not_return_bool_fails() {
	let sender: AccountId = ALICE.into();
	let beneficiary: AccountId = BOB.into();
	let revive_account = pallet_revive::Pallet::<Runtime>::account_id();
	let checking_account =
		asset_hub_westend_runtime::xcm_config::ERC20TransfersCheckingAccount::get();
	let initial_wnd_amount = 10_000_000_000_000u128;

	ExtBuilder::<Runtime>::default().build().execute_with(|| {
		// Bring the revive account to life.
		assert_ok!(Balances::mint_into(&revive_account, initial_wnd_amount));

		// Fund all accounts involved.
		assert_ok!(Balances::mint_into(&sender, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&beneficiary, initial_wnd_amount));
		assert_ok!(Balances::mint_into(&checking_account, initial_wnd_amount));

		// This contract implements the ERC20 interface for `transfer` except it returns a uint256.
		let code = compile_module_with_type("MyTokenFake", FixtureType::Resolc)
			.expect("compile ERC20")
			.0;

		let initial_amount_u256 = U256::from(1_000_000_000_000u128);
		let constructor_data = sol_data::Uint::<256>::abi_encode(&initial_amount_u256);

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
	});
}
```
