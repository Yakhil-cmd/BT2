No vulnerability found for this question.

The external report describes an unprotected low-level `.call{value:}()` in a Solidity `WalletImpl` contract with no reentrancy guard. The polkadot-sdk analog area (contract-to-contract value calls) already implements dedicated, tested reentrancy protection rather than lacking it.

In `pallet_contracts`, every cross-contract `call` checks `allows_reentry` before pushing a new frame and denies re-entrant calls into a frame that disallowed it via `Error::<T>::ReentranceDenied` [1](#0-0) .

In `pallet_revive`, the newer `ReentrancyProtection` enum formalizes three levels — `AllowReentry`, `Strict`, and `AllowNext` — explicitly designed to guard against exactly the class of bug in the report (unprotected forwarding of value/gas to an untrusted callee) [2](#0-1) . The call path enforces `Strict` by default for PVM calls unless the caller explicitly sets `ALLOW_REENTRY`, and denies reentry via `ReentranceDenied` when violated [3](#0-2) [4](#0-3) . For EVM-compatible gas-stipend semantics (mirroring Solidity's `.transfer`/`.send`), the interpreter detects the 2300-gas stipend heuristic and applies `AllowNext` protection specifically to prevent the callee from re-entering with another external call, matching (and testing) the very scenario in the report [5](#0-4) . This is covered by dedicated fixtures and tests, including a `ReentrancyAttacker` contract and tests asserting reentrancy attempts fail (`evm_call_stipend_prevents_transfer_reentrancy`, `evm_call_stipend_prevents_send_reentrancy`) [6](#0-5) [7](#0-6) .

Additionally, unlike raw Solidity `.call`, calls into the runtime dispatch precompile are explicitly reentry-guarded (`ReenteredPallet`) [8](#0-7) .

Since the FRAME/pallet-revive analog already implements, defaults to, and tests strict reentrancy protection for value-transferring calls — the inverse of the reported "no gas limit, no reentrancy guard" condition — there is no demonstrable violated invariant or missing check to report as an analog.

### Citations

**File:** substrate/frame/contracts/src/exec.rs (L1271-1279)
```rust
		// Before pushing the new frame: Protect the caller contract against reentrancy attacks.
		// It is important to do this before calling `allows_reentry` so that a direct recursion
		// is caught by it.
		self.top_frame_mut().allows_reentry = allows_reentry;

		let try_call = || {
			if !self.allows_reentry(&to) {
				return Err(<Error<T>>::ReentranceDenied.into());
			}
```

**File:** substrate/frame/revive/src/exec.rs (L122-142)
```rust
/// Level of reentrancy protection.
///
/// This needs to be specifed when a contract makes a message call. This way the calling contract
/// can specify the level of re-entrancy protection while the callee (and it's recursive callees) is
/// executing.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ReentrancyProtection {
	/// Don't activate reentrancy protection
	AllowReentry,
	/// Activate strict reentrancy protection. The direct callee and none of its own recursive
	/// callees must be the calling contract.
	Strict,
	/// Activate reentrancy protection where the direct callee can be the same contract as the
	/// caller but none of the recursive callees of the callee must be the caller.
	///
	/// This is used for calls that transfer value but restrict gas so that the callee only has a
	/// stipend gas amount. In Ethereum that is not sufficient for the callee to make another call.
	/// However, due to gas scale differences that guarantee does not automatically hold in revive
	/// and we enforce it explicitly here.
	AllowNext,
}
```

**File:** substrate/frame/revive/src/exec.rs (L2249-2274)
```rust
		// Before pushing the new frame: Protect the caller contract against reentrancy attacks.
		// It is important to do this before calling `allows_reentry` so that a direct recursion
		// is caught by it.

		if allows_reentry == ReentrancyProtection::Strict {
			self.top_frame_mut().allows_reentry = false;
		}

		let try_call = || {
			// Enable read-only access if requested; cannot disable it if already set.
			let is_read_only = read_only || self.is_read_only();

			// We can skip the stateful lookup for pre-compiles.
			let dest = if <AllPrecompiles<T>>::get::<Self>(dest_addr.as_fixed_bytes()).is_some() {
				T::AddressMapper::to_fallback_account_id(dest_addr)
			} else {
				T::AddressMapper::to_account_id(dest_addr)
			};

			if !self.allows_reentry(&dest) {
				return Err(<Error<T>>::ReentranceDenied.into());
			}

			if allows_reentry == ReentrancyProtection::AllowNext {
				self.top_frame_mut().allows_reentry = false;
			}
```

**File:** substrate/frame/revive/src/vm/pvm.rs (L696-704)
```rust
				}

				let reentrancy = if flags.contains(CallFlags::ALLOW_REENTRY) {
					ReentrancyProtection::AllowReentry
				} else {
					ReentrancyProtection::Strict
				};

				self.ext.call(resources, &callee, value, input_data, reentrancy, read_only)
```

**File:** substrate/frame/revive/src/vm/evm/instructions/contract.rs (L193-214)
```rust
	let (add_stipend, reentracy) =
		match (value.is_zero(), gas_limit.try_into().is_ok_and(|limit: u64| limit == CALL_STIPEND))
		{
			(false, _) => (true, ReentrancyProtection::AllowReentry),
			// Heuristic: detect when solc passes `gas_limit = 2300` (the call stipend).
			// For zero-value transfer/send, solc injects `gas_limit = 2300` explicitly.
			// We apply `AllowNext` reentrancy protection and set `add_stipend = true` since the
			// raw 2300 gas value is only meaningful at Ethereum's gas scale.
			(_, true) => (true, ReentrancyProtection::AllowNext),
			(_, _) => (false, ReentrancyProtection::AllowReentry),
		};

	let call_result = match scheme {
		CallScheme::Call | CallScheme::StaticCall => interpreter.ext.call(
			&CallResources::from_ethereum_gas(gas_limit, add_stipend),
			&callee,
			value,
			input,
			// protect against rex-entrancy when we grant the stipend
			reentracy,
			scheme.is_static_call(),
		),
```

**File:** substrate/frame/revive/fixtures/contracts/Stipends.sol (L38-51)
```text
/**
 * @title ReentrancyAttacker
 * @dev On receiving ETH, attempts to call back into the sender
 */
contract ReentrancyAttacker {
    receive() external payable {
        // Classic reentrancy: try to drain more ETH from the sender.
        // We intentionally don't revert on failure so the outer transfer
        // succeeds and the test can check the balance invariant.
        msg.sender.call(
            abi.encodeWithSignature("attemptTransfer(address,uint256)", address(this), msg.value)
        );
    }
}
```

**File:** substrate/frame/revive/src/tests/stipends.rs (L125-163)
```rust
#[test]
fn evm_call_stipend_prevents_transfer_reentrancy() {
	let (code, _) = compile_module_with_type("StipendTest", FixtureType::Solc).unwrap();

	ExtBuilder::default().build().execute_with(|| {
		let _ =
			<Test as Config>::Currency::set_balance(&crate::test_utils::ALICE, 10_000_000_000_000);

		let Contract { addr, .. } =
			builder::bare_instantiate(Code::Upload(code)).build_and_unwrap_contract();

		let result = builder::bare_call(addr)
			.data(StipendTest::testTransferReentrancyCall {}.abi_encode())
			.evm_value(1_000_000_u128.into())
			.build();

		assert!(!result.result.unwrap().did_revert());
	});
}

#[test]
fn evm_call_stipend_prevents_send_reentrancy() {
	let (code, _) = compile_module_with_type("StipendTest", FixtureType::Solc).unwrap();

	ExtBuilder::default().build().execute_with(|| {
		let _ =
			<Test as Config>::Currency::set_balance(&crate::test_utils::ALICE, 10_000_000_000_000);

		let Contract { addr, .. } =
			builder::bare_instantiate(Code::Upload(code)).build_and_unwrap_contract();

		let result = builder::bare_call(addr)
			.data(StipendTest::testSendReentrancyCall {}.abi_encode())
			.evm_value(1_000_000_u128.into())
			.build();

		assert!(!result.result.unwrap().did_revert());
	});
}
```

**File:** substrate/frame/revive/src/tests/pvm.rs (L2006-2046)
```rust
#[test]
fn call_runtime_reentrancy_guarded() {
	use crate::precompiles::Precompile;
	use alloy_core::sol_types::SolInterface;
	use precompiles::{INoInfo, NoInfo};

	let precompile_addr = H160(NoInfo::<Test>::MATCHER.base_address());

	let (callee_code, _callee_hash) = compile_module("dummy").unwrap();
	ExtBuilder::default().existential_deposit(50).build().execute_with(|| {
		let min_balance = Contracts::min_balance();
		let _ = <Test as Config>::Currency::set_balance(&ALICE, 1000 * min_balance);
		let _ = <Test as Config>::Currency::set_balance(&CHARLIE, 1000 * min_balance);

		let Contract { addr: addr_callee, .. } =
			builder::bare_instantiate(Code::Upload(callee_code))
				.native_value(min_balance * 100)
				.salt(Some([1; 32]))
				.build_and_unwrap_contract();

		// Call pallet_revive call() dispatchable
		let call = RuntimeCall::Contracts(crate::Call::call {
			dest: addr_callee,
			value: 0,
			weight_limit: WEIGHT_LIMIT / 3,
			storage_deposit_limit: deposit_limit::<Test>(),
			data: vec![],
		})
		.encode();

		// Call runtime to re-enter back to contracts engine by
		// calling dummy contract
		let result = builder::bare_call(precompile_addr)
			.data(
				INoInfo::INoInfoCalls::callRuntime(INoInfo::callRuntimeCall { call: call.into() })
					.abi_encode(),
			)
			.build();
		// Call to runtime should fail because of the re-entrancy guard
		assert_err!(result.result, <Error<Test>>::ReenteredPallet);
	});
```
