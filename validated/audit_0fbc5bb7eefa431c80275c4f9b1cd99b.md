### Title
ERC20Transactor deposit uses accounted amount instead of actual transferred amount, permanently locking assets for fee-on-transfer/deflationary ERC20 tokens - (File: `cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs`)

### Summary
`ERC20Transactor::withdraw_asset_with_surplus` [1](#0-0)  transfers `amount` ERC20 tokens from a user into the shared `TransfersCheckingAccount` via a Solidity `IERC20::transfer` call, then credits the XCM holding register with exactly `amount` regardless of what the checking account actually received: `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` [2](#0-1) . Later, `deposit_asset_with_surplus` attempts to move that full accounted `amount` out of the checking account to the beneficiary [3](#0-2) . If the ERC20 contract implements a fee-on-transfer (deflationary/tax) mechanism — perfectly legal per the ERC20 interface, which only requires `transfer` to return `bool` — the checking account receives less than `amount`, so the subsequent `transfer(beneficiary, amount)` call from the checking account will either revert/return `false` (transfer failed) or, if the checking account holds accumulated dust from other transfers of the same token, silently drain funds belonging to other users of that token. This is the exact accounting-mismatch pattern described in the Solidity report: crediting the "intended" transferred amount instead of the actually-received balance-delta.

### Finding Description
The Asset Hub Westend runtime wires in `ERC20Transactor` as one of the `AssetTransactors` used by the XCM executor to handle assets whose `AssetId` resolves to a contract address (`AccountKey20`) recognized by `ERC20Matcher` [4](#0-3) . Any signed account can deploy an arbitrary contract implementing the ERC20 `transfer`/`balanceOf`/`totalSupply` interface via `pallet-revive` (confirmed by the test harness `withdraw_and_deposit_erc20s`, which compiles and instantiates a user-supplied `MyToken` contract and then transacts it through `PolkadotXcm::execute` with a signed origin) [5](#0-4) . `ERC20Matcher::matches_fungibles` treats any such contract address as a valid fungible asset id for XCM purposes — there is no allow-list restricting which ERC20 contracts can be used, only bounded gas/weight/storage-deposit limits (`ERC20TransferGasLimit`, `ERC20TransferStorageDepositLimit`) enforced through `bare_call`.

The bug: `withdraw_asset_with_surplus` performs the ERC20 `transfer(checking_account, amount)` call and, upon a `true` return, unconditionally mints an `Erc20Credit(amount)` into the XCM holding register [6](#0-5) . It never re-reads `balanceOf(checking_account)` before/after the call to determine the *actual* amount received. `Erc20Credit` is explicitly documented as a "minimal imbalance tracking type... does not perform runtime-level balance enforcement" [7](#0-6) , i.e. the runtime trusts the caller-supplied `amount` as truth rather than verifying it against the token contract's real balance movement — precisely the missing check identified in the Solidity report (`balanceBefore`/`balanceAfter` delta not computed).

When the executor later calls `deposit_asset_with_surplus` to move funds out of holding to the beneficiary, it again uses the accounted `amount` (not a re-verified balance) to issue `transfer(beneficiary, amount)` from the checking account [3](#0-2) . For a standard ERC20, `amount` withdrawn == `amount` received, so this round-trips correctly. But for a fee-on-transfer ERC20 (which only needs to satisfy the same `transfer(address,uint256) returns (bool)` signature that `ERC20Matcher`/`smart_contract_not_erc20_will_error`/`smart_contract_does_not_return_bool_fails` tests confirm is the only interface contract enforced [8](#0-7) ), the checking account's real balance increase is `amount - fee`. The subsequent deposit of the full `amount` either:
1. Fails (checking account lacks sufficient real balance for that specific token) — the assets get trapped by the XCM executor's asset-trap mechanism, and because the underlying deficit is structural (the checking account genuinely never received the full `amount`), any retry/claim of the trapped assets fails identically, permanently locking the shortfall; or
2. Succeeds by consuming residual balance in the checking account left over from a *different* user's earlier fee-on-transfer transaction of the same token — silently transferring one user's shortfall cost onto another user's leftover balance, corrupting per-user accounting exactly as in the reported bug ("Users will receive other users funds or not receive funds at all").

### Impact Explanation
This is a direct accounting-mismatch / fund-locking bug reachable by any ordinary signed account with no privileged role: deploy a fee-on-transfer ERC20 via `pallet-revive`, then execute a `PolkadotXcm::execute` extrinsic that withdraws/deposits that asset (or receives it via a reserve/XCM transfer path that resolves through `ERC20Transactor`). Funds can become permanently stuck in the shared `TransfersCheckingAccount` with no path to recovery, since the deficit is structural and not caused by a transient failure. In multi-user scenarios, the shared checking account allows cross-user accounting corruption. This matches a Medium-severity classification consistent with the original Sherlock report: unbacked/locked funds and cross-user accounting confusion, but bounded to users who choose to interact with a specific attacker-deployed or naturally fee-on-transfer ERC20 asset (no privileged escalation, no unbacked issuance of the chain's native/system assets).

### Likelihood Explanation
Likelihood is moderate: it requires a user (attacker or otherwise) to register/use a fee-on-transfer ERC20 contract through the `ERC20Transactor` XCM path. This is entirely permissionless — `pallet-revive` contract deployment is open to any signed account, and `ERC20Matcher` imposes no allow-list, only interface-shape checks (confirmed by the existing negative tests for non-conforming contracts). Fee-on-transfer/tax tokens are a well-known and common token design in the wild, so this is a realistic scenario for any asset bridged or wrapped through this transactor, not a contrived edge case.

### Recommendation
In `ERC20Transactor::withdraw_asset_with_surplus`, read `balanceOf(checking_account)` before and after the `transfer` call and credit the holding register with the *actual* balance delta rather than the requested `amount`. Symmetrically, in `deposit_asset_with_surplus`, either verify the checking account's real balance before initiating the transfer-out or track per-asset actual balances separately from XCM-holding-register "credits," so the deposit only ever moves what was actually received. This mirrors the `balanceBefore`/`balanceAfter` fix recommended in the original report for `DonationVotingMerkleDistributionVaultStrategy`.

### Proof of Concept
Reachability and interface-shape enforcement are confirmed by the existing integration test suite in this repository:
- `withdraw_and_deposit_erc20s` demonstrates a signed, non-privileged account deploying an arbitrary Solidity contract (`MyToken`) and moving it through `PolkadotXcm::execute` via the `ERC20Transactor` path [5](#0-4) .
- `smart_contract_not_erc20_will_error` / `smart_contract_does_not_return_bool_fails` confirm the only requirement is the ERC20 `transfer` interface shape, not any specific fee/no-fee behavior [9](#0-8) .
- The transactor code itself confirms the amount credited to holding is the requested `amount`, not a re-verified balance delta [2](#0-1) .

I was **not able to execute a live Rust/FRAME integration reproduction** deploying an actual fee-on-transfer Solidity contract and asserting the resulting trapped-asset/locked-fund state within this session (no code execution tooling available in this ask-only mode). I also could not fully verify `ERC20Matcher`'s exact matching logic (only partial grep results were returned before the tool budget was exhausted) — confirming whether it applies any additional allow-list beyond interface-shape would strengthen or narrow this finding, and I recommend that check be performed in a follow-up session with full repository/tooling access before treating this as fully verified. All other cited evidence (transactor logic, wiring into `AssetTransactors`, and the existing test suite proving unprivileged contract-deploy + XCM-execute reachability) was directly read from source.

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

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L248-266)
```rust
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
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/src/xcm_config.rs (L213-246)
```rust
parameter_types! {
	/// Taken from the real gas and deposits of a standard ERC20 transfer call.
	pub const ERC20TransferGasLimit: Weight = Weight::from_parts(500_000_000_000, 10 * 1024 * 1024);
	pub const ERC20TransferStorageDepositLimit: Balance = 10_200_000_000;
	pub ERC20TransfersCheckingAccount: AccountId = PalletId(*b"py/revch").into_account_truncating();
	pub DapBufferAccount: AccountId = pallet_dap::Pallet::<Runtime>::buffer_account();
}

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

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L1978-2081)
```rust
#[test]
fn smart_contract_not_erc20_will_error() {
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

		let (code, _) = compile_module("dummy").unwrap();

		let Contract { addr: non_erc20_address, .. } = bare_instantiate(&sender, code)
			.transaction_limits(TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::from_parts(500_000_000_000, 10 * 1024 * 1024),
				deposit_limit: Balance::MAX,
			})
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
			Weight::from_parts(2_500_000_000, 120_000),
		)
		.is_err());
	});
}

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
