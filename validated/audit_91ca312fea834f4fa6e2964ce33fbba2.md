The Connext bug's core defect is: an EVM contract executor calls `token.transfer` for a nominal `amount`, then unconditionally credits/spends that same nominal `amount` in downstream accounting, even though a non-standard ("fee-on-transfer") ERC20 may move a different real amount. I found a structurally identical pattern in Polkadot SDK's `ERC20Transactor`, the XCM `TransactAsset` implementation Asset Hub Westend uses to let XCM programs move Solidity ERC20 tokens deployed on `pallet-revive`.

### Title
ERC20Transactor credits/spends the nominal XCM transfer amount without verifying the actual ERC20 balance moved, allowing fee-on-transfer tokens to desynchronize the shared checking-account ledger from real balances - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` and `deposit_asset_with_surplus` invoke the target ERC20 contract's `transfer()` function for the exact `amount` requested by the XCM program, and treat the call as fully successful as soon as the Solidity call returns `true`, without ever checking the actual balance delta of the shared `ERC20TransfersCheckingAccount`. Since the ERC20 contract address is fully attacker-controlled (any user can deploy arbitrary Solidity via `pallet-revive`) and is referenced by an unprivileged `pallet-xcm::execute` call, an attacker can deploy a fee-on-transfer / rebasing ERC20 and cause the XCM holding-register accounting to diverge from the real balance sitting in the shared checking account.

### Finding Description
`ERC20Transactor` is registered as an `AssetTransactor` for Asset Hub Westend at [1](#0-0) , and it matches any XCM `Asset` whose location resolves to an `AccountKey20` Solidity contract address via `ERC20Matcher`.

On `withdraw_asset_with_surplus`, the transactor calls `IERC20::transferCall { to: checking_address, value: amount }` on behalf of the withdrawing account, and if the raw call succeeds and decodes to `true`, it unconditionally credits the XCM holding register with the *full nominal* `amount`: [2](#0-1) 

There is no check of the checking account's actual ERC20 balance before/after the call - only the boolean return value of `transfer()` is inspected. A fee-on-transfer (or otherwise non-standard) ERC20 can return `true` while moving less than `amount` into the checking account (e.g., skimming a percentage back to the attacker or burning it), yet the holding register still believes the checking account received the full `amount`.

Symmetrically, `deposit_asset_with_surplus` calls `IERC20::transferCall { to: beneficiary, value: amount }` *from* the shared checking account and, again, only checks the boolean success flag, not the beneficiary's actual received balance: [3](#0-2) 

The `TransfersCheckingAccount` (`ERC20TransfersCheckingAccount`, `PalletId(*b"py/revch")`) is a single, chain-wide account shared by every XCM message that ever withdraws or deposits *any* ERC20 asset through this transactor: [4](#0-3) 

Because withdrawals into this shared account are accounted at nominal (not actual) value, an attacker who deploys a fee-on-transfer ERC20 can register a withdraw of `amount` that only delivers `amount - fee` into the checking account (attacker routes the skimmed fee back to themselves or an accomplice address inside their own contract code), while the XCM holding register still shows a credit of the full `amount`. If that same, or a different, message later performs `DepositAsset` for that nominal `amount` against the same ERC20 asset id, the checking account's *real* balance backing that asset id is short by the skimmed fee. As long as the shared checking account carries any residual real balance for that ERC20 (e.g., left over from other users' honest 1:1 transfers of the same token, or from earlier steps in the same attacker-controlled multi-hop XCM program), the deposit succeeds and pays out the full nominal amount - draining real balance that was not actually contributed by the withdrawer.

This is the same root-cause pattern as the Connext report: computing/crediting ledger state from the *requested* transfer amount instead of the *measured* balance delta, when the token implementation is attacker-controlled and can apply an undisclosed fee/skim on transfer.

### Impact Explanation
Because `ERC20TransfersCheckingAccount` is a single pooled account shared across all users and all ERC20 asset ids handled by this transactor, a mismatch between nominal-credit and real-balance-moved for one attacker-deployed fee-on-transfer token corrupts the checking account's real/virtual balance parity for that asset id. This can be leveraged to:
- Extract real ERC20 balance belonging to the pooled checking account that was not backed by the attacker's own deposit (theft of value from the shared custody account), if any residual balance for that asset id exists there.
- Cause deposits legitimately owed to other XCM participants for the same ERC20 asset id to fail or be shorted once the real balance is exhausted faster than the virtual credit implies (loss/freezing of funds for other users), mirroring the Connext report's "fund may be locked forever" outcome.

This aligns with the Medium-severity classification of the source report: no privileged role or governance is needed, only a permissionless contract deployment plus a permissionless `pallet-xcm::execute` call.

### Likelihood Explanation
The reachability requirements are all met by an ordinary, unprivileged actor:
- `pallet-revive` contract deployment is a normal permitted user operation.
- `pallet-xcm::execute` is callable by any signed origin and accepts arbitrary local XCM programs, as demonstrated by the existing test harness itself: [5](#0-4) 
- The `ERC20Transactor` is wired into the live `AssetTransactors` tuple for Asset Hub Westend, so any `AccountKey20` asset id in an XCM program routes into this exact code path [6](#0-5) .
- Nothing in `ERC20Transactor` validates ERC20 standard-compliance for fee-free transfers; it explicitly only checks the boolean success return (as also shown by the existing "non-bool-return" negative test), confirming no balance-delta verification exists anywhere in this transactor [7](#0-6) .

The main uncertainty is whether, in practice, the shared checking account routinely carries enough residual real balance per ERC20 asset id for the "profit" leg of the attack to succeed at a given point in time; this depends on runtime usage patterns and is not something I can prove ran successfully without executing against a live/local node, which was not done here.

### Recommendation
In both `withdraw_asset_with_surplus` and `deposit_asset_with_surplus`, measure the checking account's (or beneficiary's) actual ERC20 balance immediately before and after the `transfer()` call, and use that measured delta - not the requested nominal `amount` - both for the `AssetsInHolding` credit on withdraw and for determining success/failure and any residual amount on deposit. Alternatively, explicitly document and enforce (e.g., via an allow-list or a strict post-condition check) that only standard, non-fee ERC20 contracts are eligible to be referenced by XCM `AccountKey20` asset ids on this transactor.

### Proof of Concept
No PoC was executed against a live node or existing test harness; this analysis is derived purely from static code review of `withdraw_asset_with_surplus` / `deposit_asset_with_surplus` in `erc20_transactor.rs` and their absence of any before/after balance check, cross-referenced against the existing `withdraw_and_deposit_erc20s` / `smart_contract_does_not_return_bool_fails` test scaffolding in `asset-hub-westend/tests/tests.rs`, which confirms the transactor only inspects the boolean `transfer()` return value. A full reproduction would require deploying a custom fee-on-transfer Solidity fixture (analogous to `MyToken`/`MyTokenFake`) through `bare_instantiate`, funding the shared `ERC20TransfersCheckingAccount` with residual balance for that asset id from a first "honest" transfer, then issuing a second attacker `withdraw_asset`/`deposit_asset` XCM program with the fee-on-transfer contract to demonstrate the checking account's real balance is drawn down by more than the attacker actually contributed.

### Citations

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L213-219)
```rust
parameter_types! {
	/// Taken from the real gas and deposits of a standard ERC20 transfer call.
	pub const ERC20TransferGasLimit: Weight = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024);
	pub const ERC20TransferStorageDepositLimit: Balance = 10_200_000_000;
	pub ERC20TransfersCheckingAccount: AccountId = PalletId(*b"py/revch").into_account_truncating();
	pub DapBufferAccount: AccountId = pallet_dap::Pallet::<Runtime>::buffer_account();
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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L1871-1936)
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
}
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
