No vulnerability found for this question.

Investigation summary: The report describes an application-level Solidity bug — a custom contract's `deposit()` function using a low-level `.call{}` to send `msg.value` to itself for accounting instead of directly trusting `msg.value`, which reverts because the contract lacks a `receive`/`fallback` function. This is a bug specific to that dApp's bespoke deposit accounting logic, not a structural pattern present in `polkadot-sdk`.

I checked the closest structural analogs in `pallet-revive` (the EVM-compatible contracts pallet) and cross-chain asset transactors:
- `pallet-revive`'s native value-transfer path (`Stack::transfer` and `Stack::transfer_from_origin`) properly moves funds via `T::Currency`/`transfer_with_dust`, making the existential deposit transparent to contracts rather than relying on any self-directed low-level call pattern that could revert or be manipulated. [1](#0-0) 
- The ERC20 transactor's `deposit_asset_with_surplus` invokes the actual ERC20 contract's `transfer` via `pallet_revive::Pallet::<T>::bare_call`, which is the intended and correctly-scoped interaction (not a self-call disguised as `msg.value` handling). [2](#0-1) 
- `pallet-revive`'s balance-transfer rework explicitly removed a `transfer` syscall precisely to avoid ad-hoc/self-call value-transfer semantics and align ED handling with EVM value semantics. [3](#0-2) 

None of these exhibit the reported root cause — an attacker-controlled amount being pushed through a low-level self-call substituting for `msg.value` validation, with no receive/fallback guard and potential value manipulation. This is a smart-contract application bug pattern, not a FRAME/pallet-revive/XCM protocol defect, and forcing this EVM-specific analogy onto the Polkadot SDK codebase is not supported by the code.

### Citations

**File:** substrate/frame/revive/src/exec.rs (L1804-1850)
```rust
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

		let origin = origin.account_id()?;
		let ed = <T as Config>::Currency::minimum_balance();
		let is_eth_tx = exec_config.collect_deposit_from_hold.is_some();
		with_transaction(|| -> TransactionOutcome<DispatchResult> {
			// Meter the ED deposit only after the transfer succeeds: the meter is not rolled
			// back, so metering earlier would count an ED for an account never created.
			match Ok::<(), DispatchError>(())
				.and_then(|_| {
					if is_eth_tx {
						let credit = T::FeeInfo::withdraw_txfee(ed)
							.ok_or(Error::<T>::StorageDepositNotEnoughFunds)?;
						T::Currency::resolve(to, credit)
							.map_err(|_| Error::<T>::StorageDepositNotEnoughFunds)?;
						Ok(())
					} else {
						T::Currency::transfer(origin, to, ed, Preservation::Preserve)
							.map(|_| ())
							.map_err(|_| Error::<T>::StorageDepositNotEnoughFunds.into())
					}
				})
				.and_then(|_| transfer_with_dust::<T>(from, to, value, preservation))
				.and_then(|_| meter.charge_deposit(&StorageDeposit::Charge(ed)))
			{
				Ok(_) => TransactionOutcome::Commit(Ok(())),
				Err(err) => TransactionOutcome::Rollback(Err(err)),
			}
		})
	}
```

**File:** cumulus/parachains/runtimes/assets/common/src/erc20_transactor.rs (L251-266)
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
