No vulnerability found for this question.

The Solidity `SafeTransferLib` issue centers on `safeTransfer`/`safeTransferFrom` calls to a token address returning false success when no contract code exists at that address. Searching the Polkadot SDK, the closest analog is `pallet_revive`'s explicit design decision that "calling an address without associated code is a balance transfer" — documented in [1](#0-0) , implemented in `Ext::transfer` at [2](#0-1) , and reworked further in [3](#0-2) .

Unlike the Solidity bug, this is not a missing-check defect: the code path is intentional, mirrors EVM semantics on purpose, and is extensively covered by tests such as `transfer_to_nonexistent_account_works` [4](#0-3) , `delegate_call_missing_contract` [5](#0-4) , and `call_return_code` [6](#0-5) . When a destination account doesn't exist, the pallet actually creates it atomically by pulling the existential deposit from the origin, and reverts the whole transfer (returning `TransferFailed`/`StorageDepositNotEnoughFunds`) if funds are insufficient — it never silently reports success without moving value, which is the exact failure mode described in the Solmate report.

There is no ERC20-style "token contract" abstraction in FRAME where a `transfer` call can be routed to an address lacking any contract and falsely report success while balances go unchanged — `pallet_balances`/`pallet_assets` transfers operate directly on ledger storage rather than dispatching to arbitrary account code, so the "does the contract exist" check that Solmate's library skips has no meaningful equivalent outside of `pallet_revive`, where the behavior is deliberate, tested, and documented rather than a missing check.

### Citations

**File:** prdoc/stable2412/pr_5664.prdoc (L1-11)
```text
title: Calling an address without associated code is a balance transfer

doc:
  - audience: Runtime Dev
    description: |
     This makes pallet_revive behave like EVM where a balance transfer
     is just a call to a plain wallet.

crates:
  - name: pallet-revive
    bump: patch
```

**File:** substrate/frame/revive/src/exec.rs (L1792-1821)
```rust
	/// Transfer some funds from `from` to `to`.
	///
	/// This is a no-op for zero `value`, avoiding events to be emitted for zero balance transfers.
	///
	/// If the destination account does not exist, it is pulled into existence by transferring the
	/// ED from `origin` to the new account. The total amount transferred to `to` will be ED +
	/// `value`. This makes the ED fully transparent for contracts.
	/// The ED transfer is executed atomically with the actual transfer, avoiding the possibility of
	/// the ED transfer succeeding but the actual transfer failing. In other words, if the `to` does
	/// not exist, the transfer does fail and nothing will be sent to `to` if either `origin` can
	/// not provide the ED or transferring `value` from `from` to `to` fails.
	/// Note: This will also fail if `origin` is root.
	fn transfer<S: State>(
		origin: &Origin<T>,
		from: &T::AccountId,
		to: &T::AccountId,
		value: U256,
		preservation: Preservation,
		meter: &mut ResourceMeter<T, S>,
		exec_config: &ExecConfig<T>,
	) -> DispatchResult {
		let value = BalanceWithDust::<BalanceOf<T>>::from_value::<T>(value)
			.map_err(|_| Error::<T>::BalanceConversionFailed)?;
		if value.is_zero() {
			return Ok(());
		}

		if <System<T>>::account_exists(to) {
			return transfer_with_dust::<T>(from, to, value, preservation);
		}
```

**File:** prdoc/stable2412/pr_6187.prdoc (L1-9)
```text
title: '[pallet-revive] rework balance transfers'
doc:
- audience: Runtime Dev
  description: |-
    This PR removes the `transfer` syscall and changes balance transfers to make the existential deposit (ED) fully transparent for contracts.

    The `transfer` API is removed since there is no corresponding EVM opcode and transferring via a call introduces barely any overhead.

    We make the ED transparent to contracts by transferring the ED from the call origin to nonexistent accounts. Without this change, transfers to nonexistant accounts will transfer the supplied value minus the ED from the contracts viewpoint, and consequentially fail if the supplied value lies below the ED. Changing this behavior removes the need for contract code to handle this rather annoying corner case and aligns better with the EVM. The EVM charges a similar deposit from the gas meter, so transferring the ED from the call origin is practically the same as the call origin pays for gas.
```

**File:** substrate/frame/revive/src/exec/tests.rs (L276-349)
```rust
#[test]
fn transfer_to_nonexistent_account_works() {
	// This test verifies that a contract is able to transfer
	// some funds to a nonexistent account and that those transfers
	// are not able to reap accounts.
	ExtBuilder::default().build().execute_with(|| {
		let ed = <Test as Config>::Currency::minimum_balance();
		let value = 1024;
		let evm_value = Pallet::<Test>::convert_native_to_evm(value);
		let mut meter =
			TransactionMeter::<Test>::new_from_limits(Default::default(), u128::MAX).unwrap();

		// Transfers to nonexistent accounts should work
		set_balance(&ALICE, ed * 2);
		set_balance(&BOB, ed + value);

		assert_ok!(MockStack::transfer(
			&Origin::from_account_id(ALICE),
			&BOB,
			&CHARLIE,
			evm_value,
			Preservation::Preserve,
			&mut meter,
			&ExecConfig::new_substrate_tx(),
		));
		assert_eq!(get_balance(&ALICE), ed);
		assert_eq!(get_balance(&BOB), ed);
		assert_eq!(get_balance(&CHARLIE), ed + value);

		// Do not reap the origin account
		set_balance(&ALICE, ed);
		set_balance(&BOB, ed + value);
		assert_err!(
			MockStack::transfer(
				&Origin::from_account_id(ALICE),
				&BOB,
				&DJANGO,
				evm_value,
				Preservation::Preserve,
				&mut meter,
				&ExecConfig::new_substrate_tx(),
			),
			<Error<Test>>::StorageDepositNotEnoughFunds,
		);

		// Do not reap the sender account
		set_balance(&ALICE, ed * 2);
		set_balance(&BOB, value);
		assert_err!(
			MockStack::transfer(
				&Origin::from_account_id(ALICE),
				&BOB,
				&EVE,
				evm_value,
				Preservation::Preserve,
				&mut meter,
				&ExecConfig::new_substrate_tx(),
			),
			<Error<Test>>::TransferFailed
		);
		// The ED transfer would work. But it should only be executed with the actual transfer
		assert!(!System::account_exists(&EVE));

		assert_eq!(
			meter
				.execute_postponed_deposits(
					&Origin::from_account_id(ALICE),
					&ExecConfig::new_substrate_tx()
				)
				.unwrap(),
			StorageDeposit::Charge(ed),
			"only the successful transfer should charge the ED storage deposit",
		);
	});
```

**File:** substrate/frame/revive/src/exec/tests.rs (L422-461)
```rust
#[test]
fn delegate_call_missing_contract() {
	let missing_ch = MockLoader::insert(Call, move |_ctx, _| {
		Ok(ExecReturnValue { flags: ReturnFlags::empty(), data: Vec::new() })
	});

	let delegate_ch = MockLoader::insert(Call, move |ctx, _| {
		ctx.ext.delegate_call(&Default::default(), CHARLIE_ADDR, Vec::new())?;
		Ok(ExecReturnValue { flags: ReturnFlags::empty(), data: Vec::new() })
	});

	ExtBuilder::default().build().execute_with(|| {
		place_contract(&BOB, delegate_ch);
		set_balance(&ALICE, 100);

		let origin = Origin::from_account_id(ALICE);
		let mut meter = TransactionMeter::<Test>::new_from_limits(WEIGHT_LIMIT, 0).unwrap();

		// contract code missing should still succeed to mimic EVM behavior.
		assert_ok!(MockStack::run_call(
			origin.clone(),
			BOB_ADDR,
			&mut meter,
			U256::zero(),
			vec![],
			&ExecConfig::new_substrate_tx(),
		));

		// add missing contract code
		place_contract(&CHARLIE, missing_ch);
		assert_ok!(MockStack::run_call(
			origin,
			BOB_ADDR,
			&mut meter,
			U256::zero(),
			vec![],
			&ExecConfig::new_substrate_tx(),
		));
	});
}
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L1329-1384)
```rust
#[test]
fn call_return_code() {
	let (caller_code, _caller_hash) = compile_module("call_return_code").unwrap();
	let (callee_code, _callee_hash) = compile_module("ok_trap_revert").unwrap();
	ExtBuilder::default().existential_deposit(50).build().execute_with(|| {
		let min_balance = Contracts::min_balance();
		let _ = <Test as Config>::Currency::set_balance(&ALICE, 1000 * min_balance);
		let _ = <Test as Config>::Currency::set_balance(&CHARLIE, 1000 * min_balance);

		let bob = builder::bare_instantiate(Code::Upload(caller_code))
			.native_value(min_balance * 100)
			.build_and_unwrap_contract();

		// BOB cannot pay the ed which is needed to pull DJANGO into existence
		// this does trap the caller instead of returning an error code
		// reasoning is that this error state does not exist on eth where
		// ed does not exist. We hide this fact from the contract.
		let result = builder::bare_call(bob.addr)
			.data((DJANGO_ADDR, u256_bytes(1)).encode())
			.origin(RuntimeOrigin::signed(BOB))
			.build();
		assert_err!(result.result, <Error<Test>>::StorageDepositNotEnoughFunds);

		// Contract calls into Django which is no valid contract
		// This will be a balance transfer into a new account
		// with more than the contract has which will make the transfer fail
		let value = Pallet::<Test>::convert_native_to_evm(min_balance * 200);
		let result = builder::bare_call(bob.addr)
			.data(
				AsRef::<[u8]>::as_ref(&DJANGO_ADDR)
					.iter()
					.chain(&value.to_little_endian())
					.cloned()
					.collect(),
			)
			.build_and_unwrap_result();
		assert_return_code!(result, RuntimeReturnCode::TransferFailed);

		// Sending below the minimum balance should result in success.
		// The ED is charged from the call origin.
		let alice_before = get_balance(&ALICE_FALLBACK);
		assert_eq!(get_balance(&DJANGO_FALLBACK), 0);

		let value = Pallet::<Test>::convert_native_to_evm(1u128);
		let result = builder::bare_call(bob.addr)
			.data(
				AsRef::<[u8]>::as_ref(&DJANGO_ADDR)
					.iter()
					.chain(&value.to_little_endian())
					.cloned()
					.collect(),
			)
			.build_and_unwrap_result();
		assert_return_code!(result, RuntimeReturnCode::Success);
		assert_eq!(get_balance(&DJANGO_FALLBACK), min_balance + 1);
		assert_eq!(get_balance(&ALICE_FALLBACK), alice_before - min_balance);
```
