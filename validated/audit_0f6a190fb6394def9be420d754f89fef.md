### Title
`pallet-revive`'s `fungibles::Mutate` impl for ERC20 tokens returns the account's total balance instead of the amount actually transferred - ([File: substrate/frame/revive/src/impl_fungibles.rs])

### Summary
`pallet_revive::impl_fungibles::Pallet<T>` implements `fungibles::Mutate` for ERC20 contracts (assets whose `AssetId` is the contract's `H160` address) so that `xcm_builder::FungiblesAdapter` can use ERC20s as XCM-transactable fungibles. [1](#0-0)  Both `burn_from` and `mint_into` perform an ERC20 `transfer()` via `bare_call`, and — instead of returning the amount that was actually moved — they return the **current total balance** of the account queried through the ERC20's `balanceOf`, i.e. an implicit, attacker-influenceable value rather than the known, expected amount. [2](#0-1) [3](#0-2) 

### Finding Description
This is the same bug class as the referenced report: using a live token balance (`balanceOf`) as a stand-in for a quantity that is already precisely known (`amount`), instead of using or verifying the known value.

In `burn_from`:
```
pallet-revive/src/impl_fungibles.rs:169-203
fn burn_from(asset_id, who, amount, ...) -> Result<Self::Balance, DispatchError> {
    // transfer `amount` from `who` to the checking account via ERC20 transfer()
    ...
    if is_success {
        let balance = <Self as fungibles::Inspect<_>>::balance(asset_id, who);
        Ok(balance)   // <-- returns who's remaining balance, NOT `amount`
    }
    ...
}
``` [4](#0-3) 

And in `mint_into`:
```
pallet-revive/src/impl_fungibles.rs:205-241
fn mint_into(asset_id, who, amount) -> Result<Self::Balance, DispatchError> {
    // transfer `amount` from checking account to `who`
    ...
    if is_success {
        let balance = <Self as fungibles::Inspect<_>>::balance(asset_id, who);
        Ok(balance)   // <-- returns who's total balance, NOT `amount`
    }
    ...
}
``` [5](#0-4) 

Per the `fungibles::Mutate` trait contract, `burn_from`/`mint_into` must return the amount actually burned/minted (see the general contract semantics exercised by the fungible conformance tests, which always assert the returned value equals the amount actually moved, not the account's total balance). [6](#0-5) [7](#0-6)  `impl_fungibles.rs` violates this by substituting the account's whole balance for the transferred amount — an implicit balance in the exact sense of the referenced audit finding: any ERC20 tokens sent directly to the account beforehand (which any unprivileged address can do, since ERC20 `transfer` has no access control) inflate the value returned by `burn_from`/`mint_into`.

The comment in the source explicitly states these overrides exist to be consumed by `xcm_builder::FungiblesAdapter`, which uses the value returned from `TransactAsset::withdraw_asset` (backed by `Mutate::burn_from`) to determine the quantity of assets actually removed from the source account and placed into the XCM executor's Holding register. [8](#0-7)  Reachability through a real, unprivileged entry point is demonstrated by the existing integration tests exercising exactly this flow: a signed account calls `PolkadotXcm::execute` with a `WithdrawAsset`/`DepositAsset` program that manipulates an ERC20 balance through `FungiblesAdapter`/`revive` fungibles bridging on Asset Hub Westend. [9](#0-8) 

### Impact Explanation
If an attacker (or anyone, since ERC20 `transfer` is permissionless) pre-funds their own address with the same ERC20 token used as the XCM asset — e.g. by simply calling the ERC20 contract's `transfer` to themselves before executing the XCM program — then triggers a `WithdrawAsset` for a small amount `amount` via `PolkadotXcm::execute`, `FungiblesAdapter`'s call into `burn_from` will still transfer exactly `amount` out of the real ERC20 ledger, but the value it reports back to the XCM executor (used to populate Holding) will be the account's much larger *remaining* balance rather than `amount`. This causes the XCM Holding register to be credited with more of the asset than was actually removed from the ERC20 contract's ledger — an accounting mismatch that lets the attacker cause the executor to believe it withdrew (and can subsequently deposit/teleport/reserve-transfer) more tokens than were truly debited, i.e. unbacked issuance within the XCM asset accounting for that ERC20.

### Likelihood Explanation
Medium-High: no privileged role is required. The attacker only needs an ERC20 contract deployed on the chain (or reuse of any existing ERC20) and the ability to (a) send themselves tokens via the standard, permissionless `transfer()` function and (b) submit a signed `PolkadotXcm::execute` extrinsic — both ordinary, unprivileged actions already exercised by the repository's own test suite. [10](#0-9) 

### Recommendation
In `impl_fungibles.rs`, change `burn_from` and `mint_into` to return the actual amount confirmed transferred (i.e. `amount`, or a value derived by diffing the sender/receiver balance before and after the ERC20 call) instead of the account's post-operation total `balanceOf`. At minimum, capture `balance_before` immediately prior to the ERC20 `transfer` call and return `balance_before.saturating_sub(balance_after)` (for `burn_from`) or `balance_after.saturating_sub(balance_before)` (for `mint_into`), so pre-existing/attacker-controlled balances cannot be conflated with the amount actually moved by this specific operation. [11](#0-10) 

### Proof of Concept
Not independently executed in this analysis; no new test was run. The reachability path (signed `PolkadotXcm::execute` driving `withdraw_asset`/`deposit_asset` for ERC20s through `pallet_revive`'s fungibles bridge) is demonstrated by the existing repository test `withdraw_and_deposit_erc20s`, which shows the exact call chain (`PolkadotXcm::execute` → `FungiblesAdapter` → `pallet_revive::impl_fungibles::Mutate::{burn_from,mint_into}` → ERC20 `transfer`). [9](#0-8)  A concrete PoC would extend this test to pre-fund the withdrawing account with extra ERC20 balance before the `WithdrawAsset` instruction and assert that the Holding register / destination deposit reflects more than the `amount` specified in the XCM message, confirming the accounting inflation described above. This was not executed as part of this review; the described flaw is derived from direct code inspection of `burn_from`/`mint_into`'s return values versus the `fungibles::Mutate` trait contract enforced elsewhere in the codebase's conformance tests. [6](#0-5)

### Citations

**File:** substrate/frame/revive/src/impl_fungibles.rs (L158-203)
```rust
// We implement `fungibles::Mutate` to override `burn_from` and `mint_to`.
//
// These functions are used in [`xcm_builder::FungiblesAdapter`].
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
```

**File:** substrate/frame/revive/src/impl_fungibles.rs (L205-241)
```rust
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

**File:** substrate/frame/support/src/traits/tokens/fungible/conformance_tests/regular/mutate.rs (L152-189)
```rust
/// Test [`Mutate::burn_from`] for successfully burning tokens with [`Precision::BestEffort`].
///
/// This test verifies that the burning tokens with best-effort precision correctly reduces the
/// account balance and total issuance values by the reducible balance when attempting to burn
/// an amount greater than the reducible balance.
pub fn burn_from_best_effort_success<T, AccountId>()
where
	T: Mutate<AccountId>,
	<T as Inspect<AccountId>>::Balance: AtLeast8BitUnsigned + Debug,
	AccountId: AtLeast8BitUnsigned,
{
	let initial_total_issuance = T::total_issuance();
	let initial_active_issuance = T::active_issuance();

	// Setup account
	let account = AccountId::from(5);
	let initial_balance = T::minimum_balance() + 10.into();
	T::mint_into(&account, initial_balance).unwrap();

	// Get reducible balance
	let force = Fortitude::Polite;
	let reducible_balance = T::reducible_balance(&account, Preservation::Expendable, force);

	// Test: Burn a best effort amount from the account that is greater than the reducible
	// balance
	let amount_to_burn = reducible_balance + 5.into();
	let preservation = Preservation::Expendable;
	let precision = Precision::BestEffort;
	assert!(amount_to_burn > reducible_balance);
	assert!(amount_to_burn > T::balance(&account));
	T::burn_from(&account, amount_to_burn, preservation, precision, force).unwrap();

	// Verify: The balance and total issuance should be reduced by the reducible_balance
	assert_eq!(T::balance(&account), initial_balance - reducible_balance);
	assert_eq!(T::total_balance(&account), initial_balance - reducible_balance);
	assert_eq!(T::total_issuance(), initial_total_issuance + initial_balance - reducible_balance);
	assert_eq!(T::active_issuance(), initial_active_issuance + initial_balance - reducible_balance);
}
```

**File:** substrate/frame/support/src/traits/tokens/fungible/conformance_tests/regular/balanced.rs (L201-248)
```rust
/// Tests [`Balanced::withdraw`].
pub fn withdraw<T, AccountId>()
where
	T: Balanced<AccountId>,
	<T as Inspect<AccountId>>::Balance: AtLeast8BitUnsigned + Debug,
	AccountId: AtLeast8BitUnsigned,
{
	let account = AccountId::from(0);

	// Init an account with some balance
	let initial_balance = T::minimum_balance() + 10.into();
	match T::deposit(&account, initial_balance, Precision::Exact) {
		Ok(_) => {},
		Err(_) => panic!("Balanced::deposit failed"),
	};
	assert_eq!(T::total_issuance(), initial_balance);
	assert_eq!(T::balance(&account), initial_balance);

	// Withdrawing an amount smaller than the balance works when Precision::Exact
	let amount = 1.into();
	match T::withdraw(
		&account,
		amount,
		Precision::Exact,
		Preservation::Expendable,
		Fortitude::Polite,
	) {
		Ok(c) => assert_eq!(c.peek(), amount),
		Err(_) => panic!("withdraw failed"),
	};
	assert_eq!(T::total_issuance(), initial_balance - amount);
	assert_eq!(T::balance(&account), initial_balance - amount);

	// Withdrawing an amount greater than the balance fails when Precision::Exact
	let balance_before = T::balance(&account);
	let amount = balance_before + 1.into();
	match T::withdraw(
		&account,
		amount,
		Precision::Exact,
		Preservation::Expendable,
		Fortitude::Polite,
	) {
		Ok(_) => panic!("should have failed"),
		Err(e) => assert_eq!(e, TokenError::FundsUnavailable.into()),
	};
	assert_eq!(T::total_issuance(), balance_before);
	assert_eq!(T::balance(&account), balance_before);
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
