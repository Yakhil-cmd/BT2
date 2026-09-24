No vulnerability found for this question.

The MyBB bug requires privileged Admin CP access with the specific "Can manage settings?" permission — the attacker already needs an authorization role to reach the vulnerable code path. Every structurally similar pattern in the Polkadot SDK (interpreting stored/administrator-supplied data as executable code) is gated the same way and is explicitly excluded by the task's constraints:

- `frame_system::Pallet::set_code` / `set_code_without_checks` / `set_storage` require `ensure_root(origin)` before writing raw runtime code or storage. [1](#0-0) 
- `pallet_contracts`/`pallet_revive`'s `set_code` extrinsic (changing a contract's code hash) is also root-gated, as shown by the "only root can execute this extrinsic" tests. [2](#0-1) [3](#0-2) 
- Contract-initiated `set_code_hash` only ever points to code that was itself uploaded/verified and charged a deposit — it does not accept unvalidated "type" strings that get executed as a scripting language. [4](#0-3) 

No user-facing, unprivileged signed extrinsic, contract call, or XCM instruction was found that stores a "settings/options" value with an attacker-chosen "type" tag that is later interpreted and executed as code (the exact invariant violated in BIT-mybb-2022-24734). All candidate analogs require Root/governance origin, which the report's method explicitly rules out as an attacker precondition. Since the underlying bug class inherently depends on a privileged administrative panel accepting unchecked "type" metadata, and FRAME's equivalent privileged paths (`set_code*`, contracts `set_code`) already correctly gate on `ensure_root`, there is no demonstrable unprivileged analog in this codebase.

### Citations

**File:** substrate/frame/system/src/lib.rs (L721-745)
```rust
		#[pallet::call_index(2)]
		#[pallet::weight((T::SystemWeightInfo::set_code(), DispatchClass::Operational))]
		pub fn set_code(origin: OriginFor<T>, code: Vec<u8>) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;
			Self::can_set_code(&code, true).into_result()?;
			T::OnSetCode::set_code(code)?;
			// consume the rest of the block to prevent further transactions
			Ok(Some(T::BlockWeights::get().max_block).into())
		}

		/// Set the new runtime code without doing any checks of the given `code`.
		///
		/// Note that runtime upgrades will not run if this is called with a not-increasing spec
		/// version!
		#[pallet::call_index(3)]
		#[pallet::weight((T::SystemWeightInfo::set_code(), DispatchClass::Operational))]
		pub fn set_code_without_checks(
			origin: OriginFor<T>,
			code: Vec<u8>,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;
			Self::can_set_code(&code, false).into_result()?;
			T::OnSetCode::set_code(code)?;
			Ok(Some(T::BlockWeights::get().max_block).into())
		}
```

**File:** substrate/frame/contracts/src/tests.rs (L3259-3266)
```rust
		// only root can execute this extrinsic
		assert_noop!(
			Contracts::set_code(RuntimeOrigin::signed(ALICE), addr.clone(), new_code_hash),
			sp_runtime::traits::BadOrigin,
		);
		assert_eq!(get_contract(&addr).code_hash, code_hash);
		assert_refcount!(&code_hash, 1);
		assert_refcount!(&new_code_hash, 0);
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L2550-2558)
```rust
		// only root can execute this extrinsic
		assert_noop!(
			Contracts::set_code(RuntimeOrigin::signed(ALICE), addr, new_code_hash),
			sp_runtime::traits::BadOrigin,
		);
		assert_eq!(get_contract(&addr).code_hash, code_hash);
		assert_refcount!(&code_hash, 1);
		assert_refcount!(&new_code_hash, 0);
		assert_eq!(System::events(), vec![]);
```

**File:** substrate/frame/contracts/src/exec.rs (L1583-1611)
```rust
	fn set_code_hash(&mut self, hash: CodeHash<Self::T>) -> DispatchResult {
		let frame = top_frame_mut!(self);
		if !E::from_storage(hash, &mut frame.nested_gas)?.is_deterministic() {
			return Err(<Error<T>>::Indeterministic.into());
		}

		let info = frame.contract_info();

		let prev_hash = info.code_hash;
		info.code_hash = hash;

		let code_info = CodeInfoOf::<T>::get(hash).ok_or(Error::<T>::CodeNotFound)?;

		let old_base_deposit = info.storage_base_deposit();
		let new_base_deposit = info.update_base_deposit(&code_info);
		let deposit = StorageDeposit::Charge(new_base_deposit)
			.saturating_sub(&StorageDeposit::Charge(old_base_deposit));

		frame.nested_storage.charge_deposit(frame.account_id.clone(), deposit);

		Self::increment_refcount(hash)?;
		Self::decrement_refcount(prev_hash);
		Contracts::<Self::T>::deposit_event(Event::ContractCodeUpdated {
			contract: frame.account_id.clone(),
			new_code_hash: hash,
			old_code_hash: prev_hash,
		});
		Ok(())
	}
```
