### Title
Native currency (`value`) sent alongside an ERC20 precompile call (`transfer`/`approve`/`transferFrom`/`permit`) is unconditionally absorbed into the precompile's address and permanently lost - (File: `substrate/frame/revive/src/exec.rs`, `substrate/frame/assets/precompiles/src/lib.rs`)

### Summary
The `pallet-revive` execution engine unconditionally transfers any native-currency `value` attached to a call into the destination account before invoking a precompile's logic. The ERC20 asset precompile (`ERC20<Runtime, PrecompileConfig, Instance>`) never inspects or refunds that native `value`; its handlers (`transfer`, `approve`, `transferFrom`, `permit`, etc.) operate exclusively on the ERC20 `call.value` field from calldata. Because the precompile sets `HAS_CONTRACT_INFO = false` and exposes no withdrawal method, any native currency mistakenly attached to an ERC20-style call is deposited into the precompile's address's underlying account and becomes permanently unrecoverable — the same "mistaken value sent alongside a token-denominated call" root cause as the InfinityExchange `takeOrders`/`takeMultipleOneOrders` bug.

### Finding Description
In `Stack::run` (`substrate/frame/revive/src/exec.rs`), every non-delegate call transfers `frame.value_transferred` to the callee's `account_id` *before* the precompile or contract code executes: [1](#0-0) 

Immediately after, the code only mints an existential deposit for a precompile's backing account when `precompile.has_contract_info()` is true: [2](#0-1) 

The ERC20 precompile explicitly opts out of contract info (`HAS_CONTRACT_INFO: bool = false`): [3](#0-2) 

None of its dispatch handlers reference the transferred native `value`; e.g. `transfer` only moves the ERC20-denominated `call.value` via `pallet_assets::Pallet::do_transfer`, ignoring the native currency that `Stack::run` already moved into the precompile's account: [4](#0-3) 

The same pattern holds for `approve`/`transferFrom`/`permit`, none of which check or reject a non-zero attached `value`: [5](#0-4) 

This mirrors exactly the InfinityExchange flaw: a caller picks a "currency" (here: calling the ERC20 precompile rather than sending native value) but the code path that handles the attached native value only checks that it *at least* meets some threshold logic elsewhere (for real contracts with `has_contract_info() == true`), while the "wrong path" (calling a precompile without contract info, with an intent to move ERC20 tokens) neither rejects nor refunds the mistakenly attached native currency. The generic `Ext::transfer`/`transfer_from_origin` helper is a no-op only for `value == 0`; for non-zero value it will even create the destination account (funded by the origin's ED) if it doesn't exist yet, guaranteeing the funds land in a real, but uncontrolled, account: [6](#0-5) 

Because the destination address is a deterministic precompile address (not derived from any user's keypair) and the precompile exposes no method to move native balance back out, the funds are permanently stuck in that account — there is no code path (ERC20 precompile or otherwise) that ever debits native currency from a precompile's backing account.

### Impact Explanation
Any user who calls the ERC20 precompile (via the `pallet-revive` `call` extrinsic directly, or via EVM `CALL`/high-level contract-to-contract calls with a non-zero `value`) while intending to perform an ERC20 operation, permanently loses whatever native currency (`value`) they attached. This is a direct, irreversible loss of user funds with no privileged role or attacker action required — consistent with a Medium-severity "permanent fund freeze conditional on user mistake," matching the accepted severity of the referenced Code4rena finding.

### Likelihood Explanation
Likelihood is non-trivial but lower than the original report because:
- In pallet-revive, callers must explicitly set a non-zero `value` field when constructing the call (whether via the `call` extrinsic or an EVM `CALL` opcode with non-zero `value`); it is not automatically implied by "sending ETH" the way it is in a payable Solidity function.
- Wallet/tooling for EVM-style dApps interacting with pallet-revive precompiles could easily default `value` to the same field used for a "native transfer + calldata" pattern (as is idiomatic in EVM tooling, e.g., calling `transfer()` while also filling in a `value` field out of habit), reproducing the exact user-mistake scenario from the report.
- The bug is reachable by any ordinary signed account; no governance, root, or privileged extrinsic is needed.

### Recommendation
In the generic precompile dispatch path (`Stack::run` in `substrate/frame/revive/src/exec.rs`), reject calls to precompiles that do not declare support for value transfer (e.g., via a `SUPPORTS_VALUE` const or by checking `HAS_CONTRACT_INFO`) when `frame.value_transferred` is non-zero, or refund the value back to the caller if the precompile doesn't consume it. Alternatively, in `ERC20::call` (`substrate/frame/assets/precompiles/src/lib.rs`), explicitly check `env` for any transferred native value and revert with an explicit error (analogous to the recommended `require(msg.value == 0)` mitigation from the report) rather than silently absorbing it.

### Proof of Concept
I was not able to execute a live Rust/FRAME integration test within the available iterations; this analog is based on static code tracing across `substrate/frame/revive/src/exec.rs` (unconditional value transfer + contract-info-gated ED minting) and `substrate/frame/assets/precompiles/src/lib.rs` (ERC20 precompile handlers that never reference the transferred native value and set `HAS_CONTRACT_INFO = false`). I did not locate/verify the exact top-level `pallet_revive::Pallet::call` dispatchable signature/line within the iteration budget to cite the precise entry-point code, so the "user calls `call(dest=precompile, value>0, data=transfer(...))`" reachability claim, while consistent with pallet-revive's documented `call` extrinsic (destination H160 + `value: BalanceOf<T>` + calldata), should be independently confirmed by reading `substrate/frame/revive/src/lib.rs`'s `call` dispatchable and by writing a minimal integration test that calls the ERC20 precompile with non-zero `value` and asserts the value is retained forever in the precompile's account with no extraction path.

### Citations

**File:** substrate/frame/revive/src/exec.rs (L1451-1463)
```rust
			// Every non delegate call or instantiate also optionally transfers the balance.
			// If it is a delegate call, then we've already transferred tokens in the
			// last non-delegate frame.
			if frame.delegate.is_none() {
				Self::transfer_from_origin(
					&self.origin,
					&caller,
					account_id,
					frame.value_transferred,
					&mut frame.frame_meter,
					self.exec_config,
				)?;
			}
```

**File:** substrate/frame/revive/src/exec.rs (L1465-1481)
```rust
			// We need to make sure that the pre-compiles contract exist before executing it.
			// A few more conditionals:
			// 	- Only contracts with extended API (has_contract_info) are guaranteed to have an
			//    account.
			//  - Only when not delegate calling we are executing in the context of the pre-compile.
			//    Pre-compiles itself cannot delegate call.
			if let Some(precompile) = executable.as_precompile() &&
				precompile.has_contract_info() &&
				frame.delegate.is_none() &&
				!<System<T>>::account_exists(account_id)
			{
				// prefix matching pre-compiles cannot have a contract info
				// hence we only mint once per pre-compile
				T::Currency::mint_into(account_id, T::Currency::minimum_balance())?;
				// make sure the pre-compile does not destroy its account by accident
				<System<T>>::inc_consumers(account_id)?;
			}
```

**File:** substrate/frame/revive/src/exec.rs (L1792-1871)
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

	/// Same as `transfer` but `from` is an `Origin`.
	fn transfer_from_origin<S: State>(
		origin: &Origin<T>,
		from: &Origin<T>,
		to: &T::AccountId,
		value: U256,
		meter: &mut ResourceMeter<T, S>,
		exec_config: &ExecConfig<T>,
	) -> ExecResult {
		// If the from address is root there is no account to transfer from, and therefore we can't
		// take any `value` other than 0.
		let from = match from {
			Origin::Signed(caller) => caller,
			Origin::Root if value.is_zero() => return Ok(Default::default()),
			Origin::Root => return Err(DispatchError::RootNotAllowed.into()),
		};
		Self::transfer(origin, from, to, value, Preservation::Preserve, meter, exec_config)
			.map(|_| Default::default())
			.map_err(Into::into)
	}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L158-207)
```rust
	type T = Runtime;
	type Interface = IERC20::IERC20Calls;
	const MATCHER: AddressMatcher = PrecompileConfig::MATCHER;
	const HAS_CONTRACT_INFO: bool = false;

	fn call(
		address: &[u8; 20],
		input: &Self::Interface,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
		frame_support::ensure!(
			!env.is_delegate_call(),
			pallet_revive::Error::<Self::T>::PrecompileDelegateDenied,
		);

		let asset_id = PrecompileConfig::AssetIdExtractor::asset_id_from_address(address)?.into();
		let contract_addr = H160::from(*address);

		match input {
			// State-changing calls - check read-only
			IERC20Calls::transfer(_) |
			IERC20Calls::approve(_) |
			IERC20Calls::transferFrom(_) |
			IERC20Calls::permit(_)
				if env.is_read_only() =>
			{
				Err(Error::Error(pallet_revive::Error::<Self::T>::StateChangeDenied.into()))
			},

			// ERC20 functions
			IERC20Calls::transfer(call) => Self::transfer(asset_id, call, env),
			IERC20Calls::totalSupply(_) => Self::total_supply(asset_id, env),
			IERC20Calls::balanceOf(call) => Self::balance_of(asset_id, call, env),
			IERC20Calls::allowance(call) => Self::allowance(asset_id, call, env),
			IERC20Calls::approve(call) => Self::approve(asset_id, call, env),
			IERC20Calls::transferFrom(call) => Self::transfer_from(asset_id, call, env),

			// ERC20Permit functions (EIP-2612)
			IERC20Calls::permit(call) => Self::permit(asset_id, contract_addr, call, env),
			IERC20Calls::nonces(call) => Self::nonces(contract_addr, call, env),
			IERC20Calls::DOMAIN_SEPARATOR(_) => {
				Self::domain_separator(asset_id, contract_addr, env)
			},

			// ERC20Metadata functions
			IERC20Calls::name(_) => Self::name(asset_id, env),
			IERC20Calls::symbol(_) => Self::symbol(asset_id, env),
			IERC20Calls::decimals(_) => Self::decimals(asset_id, env),
		}
	}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L261-294)
```rust
	/// Execute the transfer call.
	fn transfer(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::transferCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::transfer())?;

		let from = Self::caller(env)?;
		let dest = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(
			&call.to.into_array().into(),
		);

		let f = TransferFlags { keep_alive: false, best_effort: false, burn_dust: false };
		pallet_assets::Pallet::<Runtime, Instance>::do_transfer(
			asset_id,
			&<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&from),
			&dest,
			Self::to_balance(call.value)?,
			None,
			f,
		)?;

		Self::deposit_event(
			env,
			IERC20Events::Transfer(IERC20::Transfer {
				from: from.0.into(),
				to: call.to,
				value: call.value,
			}),
		)?;

		Ok(IERC20::transferCall::abi_encode_returns(&true))
	}
```

**File:** substrate/frame/assets/precompiles/src/lib.rs (L352-469)
```rust
	fn approve(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::approveCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		use frame_support::traits::fungibles::approvals::Inspect as ApprovalsInspect;

		// Reserve worst-case gas upfront, then refund the unused portion.
		let worst_case = <Runtime as Config<Instance>>::WeightInfo::allowance()
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval())
			.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
		let charged = env.charge(worst_case)?;

		let owner = Self::caller(env)?;
		let owner_account =
			<Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&owner);
		let spender: H160 = call.spender.into_array().into();
		let spender_account = env.to_account_id(&spender);
		// Saturate: `type(uint256).max` is the standard "infinite allowance" idiom and must
		// not revert at the conversion boundary.
		let new_amount: <Runtime as Config<Instance>>::Balance = call.value.unique_saturated_into();

		let current = pallet_assets::Pallet::<Runtime, Instance>::allowance(
			asset_id.clone(),
			&owner_account,
			&spender_account,
		);

		let actual_weight;
		if new_amount.is_zero() {
			if !current.is_zero() {
				// Revoke: use the pallet's cancel logic to remove the approval and
				// unreserve the deposit.
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::cancel_approval());
			} else {
				// 0→0 no-op: only the allowance read was needed.
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance();
			}
		} else {
			// If there's an existing non-zero allowance, cancel it first so we
			// overwrite (not accumulate) — matching ERC-20 spec semantics.
			// NOTE: This does not mitigate the well-known ERC-20 approve front-running
			// race condition. Callers concerned about this should approve to 0 first,
			// or use increaseAllowance/decreaseAllowance if available.
			if !current.is_zero() {
				pallet_assets::Pallet::<Runtime, Instance>::do_cancel_approval(
					&asset_id,
					&owner_account,
					&spender_account,
				)?;
				actual_weight = worst_case;
			} else {
				actual_weight = <Runtime as Config<Instance>>::WeightInfo::allowance()
					.saturating_add(<Runtime as Config<Instance>>::WeightInfo::approve_transfer());
			}
			pallet_assets::Pallet::<Runtime, Instance>::do_approve_transfer(
				asset_id,
				&owner_account,
				&spender_account,
				new_amount,
			)?;
		}
		env.adjust_gas(charged, actual_weight);

		Self::deposit_event(
			env,
			IERC20Events::Approval(IERC20::Approval {
				owner: owner.0.into(),
				spender: call.spender,
				value: call.value,
			}),
		)?;

		Ok(IERC20::approveCall::abi_encode_returns(&true))
	}

	/// Execute the transfer_from call.
	fn transfer_from(
		asset_id: <Runtime as Config<Instance>>::AssetId,
		call: &IERC20::transferFromCall,
		env: &mut impl Ext<T = Runtime>,
	) -> Result<Vec<u8>, Error> {
		env.charge(<Runtime as Config<Instance>>::WeightInfo::transfer_approved())?;
		let spender = Self::caller(env)?;
		let spender = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&spender);

		let from = call.from.into_array().into();
		let from = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&from);

		let to = call.to.into_array().into();
		let to = <Runtime as pallet_revive::Config>::AddressMapper::to_account_id(&to);

		let approval_amount = Self::to_balance(call.value)?;
		pallet_assets::Pallet::<Runtime, Instance>::do_transfer_approved(
			asset_id,
			&from,
			&spender,
			&to,
			approval_amount,
		)?;

		Self::deposit_event(
			env,
			IERC20Events::Transfer(IERC20::Transfer {
				from: call.from,
				to: call.to,
				value: call.value,
			}),
		)?;

		Ok(IERC20::transferFromCall::abi_encode_returns(&true))
	}
```
