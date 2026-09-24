## Analog Found: Unbacked ERC20 credit fabrication via untrusted contract return value in `ERC20Transactor`

### Title
XCM `ERC20Transactor` mints fungible holding credit backed by an attacker-deployed contract's return value, with no registry/allowlist check on the ERC20 address - ([File: cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs])

### Summary
The Sherlock report's root cause is that a router trusts the return value of a call into a **user-controlled, unverified contract address** to decide whether to release real backed value, with no check that the address is a legitimate, registered target. The Polkadot-SDK analog is the newly added `ERC20Transactor` XCM `TransactAsset` implementation on Asset Hub: it treats **any** `AccountKey20` location as a valid "ERC20 asset," calls `transfer()` on that address via `pallet_revive::bare_call`, and mints an `AssetsInHolding` fungible credit purely based on the boolean return value of that call - with zero verification that any real balance actually moved.

### Finding Description
`ERC20Matcher` matches ERC20 asset locations using `IsLocalAccountKey20`, which accepts **any** `Location` of the shape `(0, [AccountKey20 { .. }])`: [1](#0-0) 

There is no allowlist, no on-chain asset registry, and no check that the 20-byte key corresponds to a real, previously-known ERC20 contract - unlike `ForeignAssetsConvertedConcreteId`, which explicitly excludes local/relay locations via a filter. Any H160 address, including one the attacker just deployed themselves, is a "valid" ERC20 asset id for this transactor.

`withdraw_asset_with_surplus` (invoked by the XCM executor whenever a `WithdrawAsset` instruction references such a location) does:
1. Resolve `asset_id` = the attacker-chosen H160 address, with zero identity verification.
2. `bare_call` into that address's `transfer(checking_account, amount)`.
3. If the call doesn't revert and the ABI-decoded return value is "success," it unconditionally creates `AssetsInHolding::new_from_fungible_credit(what.id.clone(), Box::new(Erc20Credit(amount)))` for an **arbitrary attacker-chosen `amount`**. [2](#0-1) 

Nothing here verifies that the checking account's real balance changed by `amount` - the "success" signal is entirely produced by code the attacker deployed and controls. This is structurally identical to the reported bug: `withdraw()`/`redeem()` in `LMPVaultRouterBase.sol` trusted a call into an attacker-supplied contract address and used its return value to authorize release of real backed value, without verifying the target's legitimacy.

The wiring in Asset Hub Westend confirms this transactor is live in the production `AssetTransactors` tuple used by the XCM executor: [3](#0-2) 

The same trust-the-return-value pattern, without any independent balance verification, also exists in the general `fungibles::Mutate` implementation for ERC20 asset ids (`mint_into`/`burn_from`), which other consumers (e.g. anything built on `fungibles::Mutate`/`fungibles::Inspect` for these asset ids) would inherit: [4](#0-3) 

A dedicated regression test (`smart_contract_does_not_return_bool_fails`) shows the authors were aware that malformed/misleading return values are a concern for this exact call path, but the fix only rejects non-decodable/malicious return *encodings* - it does nothing to prevent a **fully attacker-written contract** that faithfully returns `true` while doing nothing real: [5](#0-4) 

### Impact Explanation
This breaks the invariant that assets placed into the XCM holding register during instruction execution are 1:1 backed by real value transferred/locked on-chain. An attacker can deploy a trivial contract whose `transfer()` always returns `true` and does nothing else, then submit a self-executed XCM (via the permitted, unprivileged `pallet_xcm::execute` extrinsic) with `WithdrawAsset` referencing that contract's address and an arbitrary amount, fabricating fungible "ERC20 credit" backed by nothing. Whether this can be escalated into stealing *other users'* pre-existing funds depends on further steps outside what could be reproduced here (e.g. whether `pallet-asset-conversion` pool creation for such an asset id is unrestricted, and whether any cross-chain reserve/teleport path would accept this asset id as backed) - those steps were not verified with an executed reproduction, so I am not claiming a confirmed complete fund-drain chain, only a confirmed and reachable invariant violation (fabrication of unbacked fungible credit) at the `TransactAsset` boundary.

### Likelihood Explanation
High for the invariant violation itself: the entry point is a normal signed extrinsic (`pallet_xcm::execute` or any XCM program routed through the executor with a `WithdrawAsset` for an `AccountKey20` asset), requiring no privileged role, no validator/relayer collusion, and only the cost of deploying one trivial contract on Asset Hub (revive) and paying ordinary transaction fees. No governance action or stolen keys are needed.

### Recommendation
- Require `ERC20Matcher`/`IsLocalAccountKey20` to only match a **registered/allowlisted** set of ERC20 contract addresses (mirroring how `ForeignAssetsConvertedConcreteId` restricts by location), analogous to the report's own recommendation of "introduce a way to identify the vault via a mapping."
- In `withdraw_asset_with_surplus`/`deposit_asset_with_surplus` and `impl_fungibles.rs`'s `mint_into`/`burn_from`, independently verify the checking account's real balance delta rather than solely trusting the callee's returned boolean.

### Proof of Concept
No test was executed against a running node/runtime in this investigation (per constraints, I did not fabricate or claim execution results). The traced reproduction path, not executed, would be:
1. Deploy (via `pallet_revive`) a minimal PVM/EVM contract at address `EVIL` whose `transfer(address,uint256)` always returns `true` without any state change.
2. Submit `pallet_xcm::execute` with an XCM program: `WithdrawAsset(AccountKey20{ key: EVIL }, amount=N)` followed by `DepositAsset` to the attacker's own beneficiary (or any further instruction consuming the holding register).
3. Expected (per code trace): `ERC20Transactor::withdraw_asset_with_surplus` calls `EVIL.transfer(checking_account, N)`, decodes `true`, and credits `AssetsInHolding` with `N` units of asset `EVIL` with zero real backing - reproducing the "trust an attacker-controlled contract's return value to authorize value movement" root cause from the original report.

Guards checked and found insufficient: `IsLocalAccountKey20` (no allowlist) [6](#0-5) ; return-value decode check only rejects malformed encodings, not truthful-but-fake success [7](#0-6) .

### Citations

**File:** cumulus/parachains/runtimes/assets/common/src/lib.rs (L132-159)
```rust
/// `Contains<Location>` implementation that matches locations with no parents,
/// a `PalletInstance` and an `AccountKey20` junction.
pub struct IsLocalAccountKey20;
impl Contains<Location> for IsLocalAccountKey20 {
	fn contains(location: &Location) -> bool {
		matches!(location.unpack(), (0, [AccountKey20 { .. }]))
	}
}

/// Fallible converter from a location to a `H160` that matches any location ending with
/// an `AccountKey20` junction.
pub struct AccountKey20ToH160;
impl MaybeEquivalence<Location, H160> for AccountKey20ToH160 {
	fn convert(location: &Location) -> Option<H160> {
		match location.unpack() {
			(0, [AccountKey20 { key, .. }]) => Some((*key).into()),
			_ => None,
		}
	}

	fn convert_back(key: &H160) -> Option<Location> {
		Some(Location::new(0, [AccountKey20 { key: (*key).into(), network: None }]))
	}
}

/// [`xcm_executor::traits::MatchesFungibles`] implementation that matches
/// ERC20 tokens.
pub type ERC20Matcher =
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

**File:** substrate/frame/revive/src/impl_fungibles.rs (L161-241)
```rust
impl<T: Config> fungibles::Mutate<<T as frame_system::Config>::AccountId> for Pallet<T> {
	fn burn_from(
		asset_id: Self::AssetId,
		who: &T::AccountId,
		amount: Self::Balance,
		_: Preservation,
		_: Precision,
		_: Fortitude,
	) -> Result<Self::Balance, DispatchError> {
		let checking_account_eth = T::AddressMapper::to_address(&Self::checking_account());
		let checking_address = Address::from(Into::<[u8; 20]>::into(checking_account_eth));
		let data =
			IERC20::transferCall { to: checking_address, value: EU256::from(amount) }.abi_encode();
		let ContractResult { result, weight_consumed, .. } = Self::bare_call(
			OriginFor::<T>::signed(who.clone()),
			asset_id,
			U256::zero(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: WEIGHT_LIMIT,
				deposit_limit:
					<<T as pallet::Config>::Currency as fungible::Inspect<_>>::total_issuance(),
			},
			data,
			&ExecConfig::new_substrate_tx(),
		);
		log::trace!(target: "whatiwant", "{weight_consumed}");
		if let Ok(return_value) = result {
			if return_value.did_revert() {
				Err("Contract reverted".into())
			} else {
				let is_success =
					bool::abi_decode_validate(&return_value.data).expect("Failed to ABI decode");
				if is_success {
					let balance = <Self as fungibles::Inspect<_>>::balance(asset_id, who);
					Ok(balance)
				} else {
					Err("Contract transfer failed".into())
				}
			}
		} else {
			Err("Contract out of gas".into())
		}
	}

	fn mint_into(
		asset_id: Self::AssetId,
		who: &T::AccountId,
		amount: Self::Balance,
	) -> Result<Self::Balance, DispatchError> {
		let eth_address = T::AddressMapper::to_address(who);
		let address = Address::from(Into::<[u8; 20]>::into(eth_address));
		let data = IERC20::transferCall { to: address, value: EU256::from(amount) }.abi_encode();
		let ContractResult { result, .. } = Self::bare_call(
			OriginFor::<T>::signed(Self::checking_account()),
			asset_id,
			U256::zero(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: WEIGHT_LIMIT,
				deposit_limit:
					<<T as pallet::Config>::Currency as fungible::Inspect<_>>::total_issuance(),
			},
			data,
			&ExecConfig::new_substrate_tx(),
		);
		if let Ok(return_value) = result {
			if return_value.did_revert() {
				Err("Contract reverted".into())
			} else {
				let is_success =
					bool::abi_decode_validate(&return_value.data).expect("Failed to ABI decode");
				if is_success {
					let balance = <Self as fungibles::Inspect<_>>::balance(asset_id, who);
					Ok(balance)
				} else {
					Err("Contract transfer failed".into())
				}
			}
		} else {
			Err("Contract out of gas".into())
		}
	}
```

**File:** cumulus/parachains/runtimes/assets/asset-hub-westend/tests/tests.rs (L2026-2080)
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
```
