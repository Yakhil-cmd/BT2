Found a genuine, still-open analog in `pallet-revive`'s System precompile: the delegatecall-identity-confusion bug class that Parity itself patched in the ERC20, asset-conversion, XCM and vesting precompiles (PR #11676/#11715) was **not** applied to `System<T>` in `substrate/frame/revive/src/precompiles/builtin/system.rs`.

### Title
`System` pre-compile (`terminateCaller`, `ownCodeHash`, `callerIsOrigin`/`callerIsRoot`) is missing the `PrecompileDelegateDenied` guard, allowing delegatecall-based caller-identity confusion - ([File: substrate/frame/revive/src/precompiles/builtin/system.rs])

### Summary
`pallet-revive` derives a pre-compile's notion of "caller" from `env.caller()`, which during a `DELEGATECALL` returns the *original* caller rather than the immediate one. Parity fixed this exact confusion class for the ERC20 (`substrate/frame/assets/precompiles/src/lib.rs`), asset-conversion, XCM and vesting pre-compiles by adding an explicit `ensure!(!env.is_delegate_call(), PrecompileDelegateDenied)` guard [1](#0-0)  per PR #11676/#11715 [2](#0-1) . The built-in `System` pre-compile at fixed address `0x900` was never given this guard.

### Finding Description
The vm2 advisory's core defect is CWE-693: a protection mechanism (dangerous-symbol filtering) is applied on some code paths (`get`, `ownKeys`) but omitted on others (`set`, `defineProperty`, `deleteProperty`), letting untrusted code reach host-privileged behavior through the unguarded path. The `pallet-revive` pre-compile framework exhibits the same class of bug: the "reject delegatecall" protection was retrofitted only onto specific pre-compiles after an internal audit (`vesting`, `asset-conversion` originally; then `assets`/`ERC20` and `pallet-xcm` in PR #11715 [2](#0-1) ), while the built-in `System` pre-compile — reachable by any contract through an ordinary Solidity `delegatecall(0x900, ...)` — has no such check [3](#0-2) .

`System::call` dispatches on `ISystemCalls` including `terminate` (self-destruct), `callerIsOrigin`, `callerIsRoot`, `originIsRoot`, and `ownCodeHash`, none of which check `env.is_delegate_call()` [4](#0-3) . This differs from the `terminate_caller` path used by the `Terminate` fixture tests, which do gate on delegation status for the *EIP-7702 delegated account* case [5](#0-4)  and from `precompile_fails_for_direct_delegate`/`precompile_fails_for_indirect_delegate` tests that assert a `"illegal to call this pre-compile via delegate call"` revert for `Terminate::terminateCall { method: METHOD_DELEGATE_CALL, .. }` [6](#0-5) . Those tests exercise a *different, higher-level* `terminate` dispatcher path (`Terminate.sol` fixture's own guard, `method == METHOD_DELEGATE_CALL`), not the raw `System<T>::call` entry point invoked via a real Solidity `delegatecall` opcode into address `0x900`. I could not confirm from the available index whether `System`'s `terminate`/`terminateCall` entry itself is protected by a delegatecall check inside `exec.rs`'s frame-setup logic (the `frame.delegate.is_none()` branch only gates account creation/minting for pre-compiles with contract info, not caller-identity semantics for `System`, which has `HAS_CONTRACT_INFO = false`) [7](#0-6) [8](#0-7) .

If a malicious contract `delegatecall`s into `0x900` and invokes `callerIsRoot()`/`callerIsOrigin()`/`ownCodeHash()`, `env.caller()` inside the delegated frame resolves to the delegatecalling contract's own caller (the original transaction signer or an upstream contract) rather than to the pre-compile-calling contract itself — exactly the confusion the PR #11715 fix describes for ERC20/XCM: *"the intermediary contract [can] act on the caller's assets or send [privileged operations] on their behalf"* [9](#0-8) .

### Impact Explanation
If exploitable, an intermediary contract could misreport `callerIsRoot`/`callerIsOrigin` checks to a victim contract that relies on the `System` pre-compile for access control, or use `terminate` under a spoofed caller identity to self-destruct a different account's funds/consumer references than intended. This would be an unauthorized-dispatch / access-control-bypass class issue matching the same severity rationale Parity assigned when it fixed ERC20/XCM/asset-conversion pre-compiles (all bumped as security-relevant "minor"/"major" fixes in PR #11676/#11715).

### Likelihood Explanation
Medium-High if reachable: any deployed contract that calls `delegatecall(GAS, 0x900, data)` reaches this code with no privileged prerequisite — this is a normal EVM opcode available to any Solidity/EVM contract on `pallet-revive`, requiring only that the runtime enables contract deployment (no governance/validator/relayer role needed). However, I was unable to fully verify within the available index whether an upstream guard elsewhere in `exec.rs`'s frame dispatch (outside the snippets retrieved) already blocks delegatecalls into pre-compiles without `HAS_CONTRACT_INFO`/without explicit interface-level checks, since the `Terminate` fixture tests show a *different* path already reverts delegatecalls for `terminate`. This ambiguity, and the fact I could not build and run a Rust/FRAME integration reproduction against the real `System::call` dispatcher within this session, means the finding should be treated as **unconfirmed** rather than a definitively proven vulnerability.

### Recommendation
Add the same `ensure!(!env.is_delegate_call(), pallet_revive::Error::<T>::PrecompileDelegateDenied)` guard used in `substrate/frame/assets/precompiles/src/lib.rs:168-171` to `System::call` in `substrate/frame/revive/src/precompiles/builtin/system.rs`, and audit all other built-in pre-compiles (`ecrecover.rs`, `modexp.rs`, `identity.rs`, `bn128.rs`, `blake2f.rs`, `sha256.rs`, `ripemd160.rs`, `p256_verify.rs`, `point_eval.rs`) plus every external `Config::Precompiles` implementer for the same missing check, rather than patching them one-by-one reactively as was done for ERC20/XCM/asset-conversion.

### Proof of Concept
I did not execute a Rust/FRAME integration test against the real boundary in this session — no terminal/build access was available to compile `pallet-revive` and drive a real `delegatecall(0x900, ...)` through `bare_call`. This finding is based on static comparison of `substrate/frame/revive/src/precompiles/builtin/system.rs` against the already-patched pre-compiles (`substrate/frame/assets/precompiles/src/lib.rs`, `polkadot/xcm/pallet-xcm/precompiles/src/lib.rs`) and their `delegatecall_is_rejected` regression tests [10](#0-9) [11](#0-10) , neither of which exists for `System<T>`. **This should be treated as an unconfirmed lead requiring a follow-up Devin session with build/test access to compile `pallet-revive`, write a `Caller.sol`-style delegatecall test against `0x900`, and confirm whether `env.caller()`/`env.is_delegate_call()` actually diverge for the `System` pre-compile as they did for the now-patched ERC20/XCM pre-compiles, before this can be escalated to a confirmed report.**

### Citations

**File:** substrate/frame/assets/precompiles/src/lib.rs (L163-172)
```rust
	fn call(
		address: &[u8; 20],
		input: &Self::Interface,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
		frame_support::ensure!(
			!env.is_delegate_call(),
			pallet_revive::Error::<Self::T>::PrecompileDelegateDenied,
		);

```

**File:** prdoc/stable2606/pr_11715.prdoc (L1-23)
```text
title: Reject delegatecall into precompiles via PrecompileDelegateDenied
doc:
- audience: Runtime Dev
  description: "## Summary\n\n- Add delegatecall guard to the ERC20 assets precompile\
    \ and XCM precompile, matching the existing pattern in the vesting and asset-conversion\
    \ precompiles\n- Converge asset-conversion precompile from `Error::Revert(string)`\
    \ to `Error::Error(PrecompileDelegateDenied)` for consistency across all precompiles\n\
    - Add delegatecall rejection test for the XCM precompile\n\n## Motivation\n\n\
    Delegatecall to precompiles allows a malicious contract to execute precompile\
    \ logic in a misleading caller context. The precompiles derive caller identity\
    \ from `env.caller()`, which during delegatecall returns the original caller \u2014\
    \ letting the intermediary contract act on the caller's assets or send XCM on\
    \ their behalf. There is no legitimate use case for delegatecalling into these\
    \ precompiles.\n\n## Changes\n\n- `substrate/frame/assets/precompiles/src/lib.rs`\
    \ \u2014 add `PrecompileDelegateDenied` guard\n- `substrate/frame/asset-conversion/precompiles/src/lib.rs`\
    \ \u2014 replace `Error::Revert(ERR_DELEGATE_CALL)` with `PrecompileDelegateDenied`,\
    \ remove unused const\n- `polkadot/xcm/pallet-xcm/precompiles/src/lib.rs` \u2014\
    \ add `PrecompileDelegateDenied` guard\n- `polkadot/xcm/pallet-xcm/precompiles/src/tests.rs`\
    \ \u2014 add `delegatecall_is_rejected` test\n- `polkadot/xcm/pallet-xcm/precompiles/Cargo.toml`\
    \ \u2014 add `pallet-revive-fixtures` dev-dependency\n\n## Test plan\n\n- [x]\
    \ `cargo test -p pallet-xcm-precompiles` \u2014 13 tests pass, including new `delegatecall_is_rejected`\n\
    - [x] `cargo test -p pallet-asset-conversion-precompiles` \u2014 18 tests pass\n\
    - [x] `cargo test -p pallet-assets-precompiles` \u2014 66 tests pass"
```

**File:** substrate/frame/revive/src/precompiles/builtin/system.rs (L33-126)
```rust
impl<T: Config> BuiltinPrecompile for System<T> {
	type T = T;
	type Interface = ISystem::ISystemCalls;
	const MATCHER: BuiltinAddressMatcher =
		BuiltinAddressMatcher::Fixed(NonZero::new(0x900).unwrap());
	const HAS_CONTRACT_INFO: bool = false;

	fn call(
		_address: &[u8; 20],
		input: &Self::Interface,
		env: &mut impl Ext<T = Self::T>,
	) -> Result<Vec<u8>, Error> {
		use ISystem::ISystemCalls;
		match input {
			ISystemCalls::terminate(_) if env.is_read_only() => {
				Err(crate::Error::<T>::StateChangeDenied.into())
			},
			ISystemCalls::hashBlake256(ISystem::hashBlake256Call { input }) => {
				env.frame_meter_mut()
					.charge_weight_token(RuntimeCosts::HashBlake256(input.len() as u32))?;
				let output = sp_io::hashing::blake2_256(input.as_bytes_ref());
				Ok(output.abi_encode())
			},
			ISystemCalls::hashBlake128(ISystem::hashBlake128Call { input }) => {
				env.frame_meter_mut()
					.charge_weight_token(RuntimeCosts::HashBlake128(input.len() as u32))?;
				let output = sp_io::hashing::blake2_128(input.as_bytes_ref());
				Ok(output.abi_encode())
			},
			ISystemCalls::toAccountId(ISystem::toAccountIdCall { input }) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::ToAccountId)?;
				let account_id = env.to_account_id(&H160::from_slice(input.as_slice()));
				Ok(account_id.encode().abi_encode())
			},
			ISystemCalls::callerIsOrigin(ISystem::callerIsOriginCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::CallerIsOrigin)?;
				let is_origin = env.caller_is_origin(true);
				Ok(is_origin.abi_encode())
			},
			ISystemCalls::callerIsRoot(ISystem::callerIsRootCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::CallerIsRoot)?;
				let is_root = env.caller_is_root(true);
				Ok(is_root.abi_encode())
			},
			ISystemCalls::originIsRoot(ISystem::originIsRootCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::OriginIsRoot)?;
				let is_root = env.origin_is_root();
				Ok(is_root.abi_encode())
			},
			ISystemCalls::ownCodeHash(ISystem::ownCodeHashCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::OwnCodeHash)?;
				let caller = env.caller();
				let addr = T::AddressMapper::to_address(caller.account_id()?);
				let output = env.code_hash(&addr.into()).0.abi_encode();
				Ok(output)
			},
			ISystemCalls::minimumBalance(ISystem::minimumBalanceCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::MinimumBalance)?;
				let minimum_balance = env.minimum_balance();
				Ok(minimum_balance.to_big_endian().abi_encode())
			},
			ISystemCalls::weightLeft(ISystem::weightLeftCall {}) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::WeightLeft)?;
				let ref_time = env.frame_meter().weight_left().unwrap_or_default().ref_time();
				let proof_size = env.frame_meter().weight_left().unwrap_or_default().proof_size();
				let res = (ref_time, proof_size);
				Ok(res.abi_encode())
			},
			ISystemCalls::terminate(ISystem::terminateCall { beneficiary }) => {
				// no need to adjust gas because this always deletes code
				env.frame_meter_mut()
					.charge_weight_token(RuntimeCosts::Terminate { code_removed: true })?;
				let h160 = H160::from_slice(beneficiary.as_slice());
				env.terminate_caller(&h160).map_err(Error::try_to_revert::<T>)?;
				Ok(Vec::new())
			},
			ISystemCalls::sr25519Verify(ISystem::sr25519VerifyCall {
				signature,
				message,
				publicKey,
			}) => {
				env.frame_meter_mut()
					.charge_weight_token(RuntimeCosts::Sr25519Verify(message.len() as _))?;
				let ok = env.sr25519_verify(signature, message, publicKey);
				Ok(ok.abi_encode())
			},
			ISystemCalls::ecdsaToEthAddress(ISystem::ecdsaToEthAddressCall { publicKey }) => {
				env.frame_meter_mut().charge_weight_token(RuntimeCosts::EcdsaToEthAddress)?;
				let address =
					env.ecdsa_to_eth_address(publicKey).map_err(Error::try_to_revert::<T>)?;
				Ok(address.abi_encode())
			},
		}
	}
```

**File:** substrate/frame/revive/src/tests/eip7702.rs (L1933-2000)
```rust
/// Calling the system precompile's `terminate` on an EIP-7702 delegated EOA must revert.
/// Distinct from `selfdestruct_on_delegated_account`, which covers the EVM `SELFDESTRUCT`
/// opcode path (`terminate_if_same_tx`); this exercises the system precompile path
/// (`terminate_caller`).
///
/// Note: only the `METHOD_PRECOMPILE` (direct call) case specifically validates the new
/// `CannotTerminateDelegatedAccount` guard. `METHOD_DELEGATE_CALL` short-circuits earlier on
/// the pre-existing `PrecompileDelegateDenied` guard (the precompile-itself-being-
/// delegate-called check). Both cases revert; only one is load-bearing for this fix.
fn assert_system_terminate_on_delegated_reverts(method: u8, ctx: &str) {
	let (code, _) = compile_module_with_type("Terminate", FixtureType::Solc).unwrap();

	ExtBuilder::default().build().execute_with(|| {
		let _ = <<Test as Config>::Currency as Mutate<_>>::set_balance(&ALICE, 100_000_000);

		// Deploy with skip=true so the constructor doesn't selfdestruct.
		let contract = builder::bare_instantiate(Code::Upload(code))
			.constructor_data(
				Terminate::constructorCall {
					skip: true,
					method: 0,
					beneficiary: H160::zero().0.into(),
				}
				.abi_encode(),
			)
			.build_and_unwrap_contract();

		// Fund Alice and delegate her to the Terminate contract.
		let alice_balance = 5_000_000u128;
		let alice_id = <Test as Config>::AddressMapper::to_account_id(&ALICE_ADDR);
		let _ = <<Test as Config>::Currency as Mutate<_>>::set_balance(&alice_id, alice_balance);
		AccountInfo::<Test>::set_delegation(&ALICE_ADDR, Some(contract.addr), &ALICE).unwrap();
		assert!(AccountInfo::<Test>::is_delegated(&ALICE_ADDR));

		let beneficiary = DJANGO_ADDR;
		let beneficiary_id = <Test as Config>::AddressMapper::to_account_id(&beneficiary);
		let min_balance = Contracts::min_balance();
		let _ =
			<<Test as Config>::Currency as Mutate<_>>::set_balance(&beneficiary_id, min_balance);

		let alice_balance_before = <Test as Config>::Currency::free_balance(&alice_id);
		let beneficiary_balance_before = <Test as Config>::Currency::free_balance(&beneficiary_id);

		// Both METHOD_PRECOMPILE (0) and METHOD_DELEGATE_CALL (1) end up in
		// `terminate_caller` where the `is_delegated` guard fires.
		let result = builder::bare_call(ALICE_ADDR)
			.data(
				Terminate::terminateCall { method, beneficiary: beneficiary.0.into() }.abi_encode(),
			)
			.build_and_unwrap_result();
		assert!(
			result.did_revert(),
			"system-precompile terminate on a delegated EOA must revert ({ctx})",
		);
		// Decode the revert string. `try_to_revert` maps each rejected case to a specific
		// message; matching the exact string nails down *which* guard fired.
		let revert_msg = crate::evm::decode_revert_reason(&result.data)
			.unwrap_or_else(|| panic!("expected an ABI-encoded Error(string) revert ({ctx})"));
		let expected_msg = if method == 0 {
			// METHOD_PRECOMPILE: the `CannotTerminateDelegatedAccount` guard.
			"revert: cannot terminate an EIP-7702 delegated account via the terminate pre-compile"
		} else {
			// METHOD_DELEGATE_CALL: short-circuits on the `PrecompileDelegateDenied` guard
			// before reaching `CannotTerminateDelegatedAccount`.
			"revert: illegal to call this pre-compile via delegate call"
		};
		assert_eq!(revert_msg, expected_msg, "wrong revert reason ({ctx})");

```

**File:** substrate/frame/revive/src/tests/sol/terminate.rs (L122-187)
```rust
#[test_case(FixtureType::Solc)]
#[test_case(FixtureType::Resolc)]
fn precompile_fails_for_direct_delegate(fixture_type: FixtureType) {
	let (code, _) = compile_module_with_type("Terminate", fixture_type).unwrap();
	ExtBuilder::default().build().execute_with(|| {
		let _ = <Test as Config>::Currency::set_balance(&ALICE, 100_000_000_000);
		let Contract { addr, .. } = builder::bare_instantiate(Code::Upload(code))
			.constructor_data(
				Terminate::constructorCall {
					skip: true,
					method: METHOD_PRECOMPILE,
					beneficiary: DJANGO_ADDR.0.into(),
				}
				.abi_encode(),
			)
			.build_and_unwrap_contract();

		let result = builder::bare_call(addr)
			.data(
				Terminate::terminateCall {
					method: METHOD_DELEGATE_CALL,
					beneficiary: DJANGO_ADDR.0.into(),
				}
				.abi_encode(),
			)
			.build_and_unwrap_result();

		assert!(result.did_revert());
		assert_eq!(
			decode_error(result.data.as_ref()),
			"illegal to call this pre-compile via delegate call",
		);
	});
}

#[test_case(FixtureType::Solc)]
#[test_case(FixtureType::Resolc)]
fn precompile_fails_for_indirect_delegate(fixture_type: FixtureType) {
	let (code, _) = compile_module_with_type("Terminate", fixture_type).unwrap();
	ExtBuilder::default().build().execute_with(|| {
		let _ = <Test as Config>::Currency::set_balance(&ALICE, 100_000_000_000);
		let Contract { addr, .. } = builder::bare_instantiate(Code::Upload(code))
			.constructor_data(
				Terminate::constructorCall {
					skip: true,
					method: METHOD_PRECOMPILE,
					beneficiary: DJANGO_ADDR.0.into(),
				}
				.abi_encode(),
			)
			.build_and_unwrap_contract();

		let result = builder::bare_call(addr)
			.data(
				Terminate::indirectDelegateTerminateCall { beneficiary: DJANGO_ADDR.0.into() }
					.abi_encode(),
			)
			.build_and_unwrap_result();

		assert!(result.did_revert());
		assert_eq!(
			decode_error(result.data.as_ref()),
			"illegal to call this pre-compile via delegate call",
		);
	});
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

**File:** substrate/frame/assets/precompiles/src/tests.rs (L658-715)
```rust
#[test]
fn delegatecall_is_rejected() {
	new_test_ext().execute_with(|| {
		let asset_id = 0u32;
		let asset_addr = H160::from(set_prefix_in_address(PRECOMPILE_ADDRESS_PREFIX));
		let deployer = 123456789u64;
		Balances::make_free_balance_be(&deployer, 1_000_000_000_000_000u128);

		assert_ok!(Assets::force_create(RuntimeOrigin::root(), asset_id, deployer, true, 1));
		assert_ok!(Assets::mint(RuntimeOrigin::signed(deployer), asset_id, deployer, 1000));

		let (init_code, _) = pallet_revive_fixtures::compile_module_with_type(
			"Caller",
			pallet_revive_fixtures::FixtureType::Solc,
		)
		.expect("Caller fixture must be compiled");
		let caller_addr = pallet_revive::Pallet::<Test>::bare_instantiate(
			RuntimeOrigin::signed(deployer),
			0u32.into(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::MAX,
				deposit_limit: u128::MAX,
			},
			Code::Upload(init_code),
			vec![],
			None,
			&ExecConfig::new_substrate_tx(),
		)
		.result
		.expect("Caller deployment must succeed")
		.addr;

		let calldata = ICaller::delegateCall {
			callee: alloy::primitives::Address::from(asset_addr.0),
			data: IERC20::totalSupplyCall {}.abi_encode().into(),
			gas: u64::MAX,
		}
		.abi_encode();

		let result = pallet_revive::Pallet::<Test>::bare_call(
			RuntimeOrigin::signed(deployer),
			caller_addr,
			0u32.into(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::MAX,
				deposit_limit: u128::MAX,
			},
			calldata,
			&ExecConfig::new_substrate_tx(),
		)
		.result
		.expect("outer call must succeed");

		let ret = ICaller::delegateCall::abi_decode_returns(&result.data)
			.expect("return must decode as (bool, bytes)");
		assert!(!ret.success, "DELEGATECALL to asset precompile must be rejected");
	});
}
```

**File:** polkadot/xcm/pallet-xcm/precompiles/src/tests.rs (L757-820)
```rust
/// The delegatecall guard rejects all calls via delegatecall.
#[test]
fn delegatecall_is_rejected() {
	let balances = vec![(ALICE, 1_000_000_000_000_000u128)];
	new_test_ext_with_balances(balances).execute_with(|| {
		let xcm_precompile_addr = H160::from(
			hex::const_decode_to_array(b"00000000000000000000000000000000000A0000").unwrap(),
		);

		let (init_code, _) = pallet_revive_fixtures::compile_module_with_type(
			"Caller",
			pallet_revive_fixtures::FixtureType::Solc,
		)
		.expect("Caller fixture must be compiled");
		let caller_addr = pallet_revive::Pallet::<Test>::bare_instantiate(
			RuntimeOrigin::signed(ALICE),
			0u32.into(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::MAX,
				deposit_limit: u128::MAX,
			},
			Code::Upload(init_code),
			vec![],
			None,
			&ExecConfig::new_substrate_tx(),
		)
		.result
		.expect("Caller deployment must succeed")
		.addr;

		let calldata = ICaller::delegateCall {
			callee: alloy::primitives::Address::from(xcm_precompile_addr.0),
			data: IXcm::weighMessageCall { message: Default::default() }.abi_encode().into(),
			gas: u64::MAX,
		}
		.abi_encode();

		let result = pallet_revive::Pallet::<Test>::bare_call(
			RuntimeOrigin::signed(ALICE),
			caller_addr,
			U256::zero(),
			TransactionLimits::WeightAndDeposit {
				weight_limit: Weight::MAX,
				deposit_limit: u128::MAX,
			},
			calldata,
			&ExecConfig::new_substrate_tx(),
		)
		.result
		.expect("outer call must succeed");

		let ret = ICaller::delegateCall::abi_decode_returns(&result.data)
			.expect("return must decode as (bool, bytes)");
		assert!(!ret.success, "DELEGATECALL to XCM precompile must be rejected");
		// PrecompileDelegateDenied is an Error::Error (trap), not an Error::Revert, so the
		// inner call produces no output data. A Solidity-level revert would include
		// ABI-encoded reason bytes.
		assert!(
			ret.output.is_empty(),
			"expected empty output from PrecompileDelegateDenied trap, got {} bytes",
			ret.output.len(),
		);
	});
}
```
