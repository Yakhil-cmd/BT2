## Analog Found: Heuristic-Based Reentrancy Classification for EVM Value-Transfer Calls in `pallet-revive`

The original report flags Solidity's `.transfer()`/`.send()` 2300-gas-stipend semantics as risky. `pallet-revive` deliberately re-implements this exact EVM semantic for compatibility when executing real EVM bytecode, and the re-implementation uses an **attacker-observable/attacker-craftable heuristic** to decide reentrancy protection, which is a legitimate FRAME-analog issue rather than a forced EVM analogy.

### Title
Reentrancy-protection heuristic for value-transfer calls is spoofable via explicit `gas=2300` in `run_call` - ([File: substrate/frame/revive/src/vm/evm/instructions/contract.rs])

### Summary
`pallet-revive`'s EVM interpreter decides whether a `CALL`/`STATICCALL` gets `ReentrancyProtection::AllowNext` (restrictive, meant only for compiler-emitted zero-value `transfer(0)`/`send(0)`) or `ReentrancyProtection::AllowReentry` (unrestricted) purely from two observable stack values: whether `value == 0` and whether the caller-supplied `gas_limit` numerically equals `CALL_STIPEND` (2300). Any contract can supply these exact values itself via a low-level `call{gas: 2300, value: 0}(...)`, which is legal Solidity/Yul and not restricted to compiler-generated `transfer`/`send` bytecode.

### Finding Description
`run_call` in [1](#0-0)  computes:
```rust
let (add_stipend, reentracy) =
    match (value.is_zero(), gas_limit.try_into().is_ok_and(|limit: u64| limit == CALL_STIPEND))
    {
        (false, _) => (true, ReentrancyProtection::AllowReentry),
        (_, true) => (true, ReentrancyProtection::AllowNext),
        (_, _) => (false, ReentrancyProtection::AllowReentry),
    };
```
This is explicitly documented as a heuristic: "detect when solc passes `gas_limit = 2300`" [2](#0-1) . The companion PR doc confirms the semantic table mapping Solidity constructs to `(value, gas)` pairs, and that the zero-value `2300` heuristic is what triggers `AllowNext` [3](#0-2) . `AllowNext` is defined project-wide as a distinct, more permissive-but-still-restricting reentrancy mode introduced specifically "to implement reentrancy protection for simple transfers with call stipends," toggled at a different point in frame creation than the `Strict` mode [4](#0-3) .

The classification, however, does not verify that the call actually originated from compiler-emitted `transfer`/`send` bytecode — it only inspects the two stack operands. A contract author (the "attacker" here needs no privileged role, just the ability to deploy an ordinary EVM contract on `pallet-revive`) can write inline low-level Yul/assembly such as `call(2300, addr, 0, ...)` to intentionally hit the `(_, true)` branch and force `AllowNext` on a call that is semantically a generic zero-value call, not a `.transfer(0)`/`.send(0)`. Conversely, any nonzero-value call — including `target.call{value: v}("")`, which per the same PR's own semantics table is supposed to forward "remaining gas" with "No stipend" — is unconditionally classified into `(false, _) => (true, AllowReentry)`, meaning `add_stipend` is force-set to `true` and 2300 extra gas is added regardless of the actual `gas_limit` requested by the caller. This means the stipend-granting/gas-accounting logic and the reentrancy-mode classification are driven by caller-supplied values that do not reliably distinguish the three genuinely different call shapes (`transfer`, `send`, `call{value}`) that the design intends to differentiate.

### Impact Explanation
Because the reentrancy mode and the (limited) extra-gas stipend are derived from spoofable stack inputs rather than from the actual call-site semantics, a contract can obtain classification results inconsistent with the modeled EVM behavior it is meant to emulate:
- A generic zero-value low-level call crafted with `gas=2300` gets treated as an `AllowNext`-protected pseudo-transfer, potentially changing reentrancy guarantees relied upon by other contracts interacting with it in ways the original EVM semantics (which use `AllowNext` only for compiler-generated stipend transfers) would not produce.
- Every nonzero-value call unconditionally receives `add_stipend = true` and `AllowReentry`, even for `call{value: v, gas: g}("")` where the real EVM/Solidity model says no automatic stipend should be added on top of `g`.

The severity is bounded to Medium/Low: it is a compatibility/consistency deviation in the EVM emulation of gas metering and reentrancy classification, not a direct fund-drain, and does not bypass storage-deposit/weight metering (the added stipend weight is still charged through `determine_call_stipend`/`CallResources`) [5](#0-4) .

### Likelihood Explanation
Any user permitted to deploy and call an EVM contract through `pallet-revive`'s `eth_transact`/`call` extrinsic path can trigger this without any privileged role, since it only requires writing an inline-assembly `call` opcode with the specific `(value, gas)` combination checked by the heuristic. The precondition (deploying an ordinary EVM contract) is the normal, unprivileged, permitted usage of `pallet-revive`.

### Recommendation
Do not classify reentrancy protection or stipend eligibility purely from the numeric coincidence of `gas_limit == CALL_STIPEND`. If distinguishing compiler-emitted `transfer`/`send` from general low-level calls is required for spec-accurate EVM emulation, track the distinction through the bytecode-level call convention/opcode metadata rather than the caller-controllable stack operands, or explicitly document and accept that this is a best-effort heuristic with known false positive/negative call classifications (i.e., not a security boundary and must not be relied upon by application contracts for reentrancy safety guarantees).

### Proof of Concept
Not executed — I do not have terminal/execution access in this session to compile and run the described `call(2300, addr, 0, ...)` Yul contract against `pallet-revive`'s test harness. A reproduction would use the existing `substrate/frame/revive/src/tests/stipends.rs` harness and `Stipends.sol`/a custom Yul fixture [6](#0-5) [7](#0-6) , adding a case that issues a raw `call(2300, target, 0, in, insize, out, outsize)` from inline assembly and asserting the frame is classified `AllowNext` via `run_call`'s heuristic in [1](#0-0) , then comparing against a semantically-equivalent `call{value: v}` case to show inconsistent stipend/reentrancy treatment. This was not run; the finding is based on static code and design-doc review of `pallet-revive`'s EVM-compatibility call-dispatch logic, not on an executed test.

### Citations

**File:** substrate/frame/revive/src/vm/evm/instructions/contract.rs (L192-203)
```rust
) -> ControlFlow<Halt> {
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
```

**File:** prdoc/stable2603/pr_11227.prdoc (L4-19)
```text
  description: "## Summary\n\nAdd tests that verify the `AllowNext` reentrancy path\
    \ is triggered for zero-value `transfer` and `send` calls.\n\n### How solc 0.8.30\
    \ handles the 2300 gas stipend\n\n| Solidity call | value | gas passed by compiler\
    \ | Stipend source |\n|---|---|---|---|\n| `target.transfer(amount)` | > 0 | `0`\
    \ | EVM adds 2300 automatically |\n| `target.send(amount)` | > 0 | `0` | EVM adds\
    \ 2300 automatically |\n| `target.transfer(0)` | 0 | `2300` | Compiler injects\
    \ explicitly |\n| `target.send(0)` | 0 | `2300` | Compiler injects explicitly\
    \ |\n| `target.call{value: v}(\"\")` | any | remaining gas | No stipend (forwards\
    \ all gas) |\n\nThe zero-value case is the one detected by our `gas_limit == CALL_STIPEND`\
    \ heuristic, which triggers `AllowNext`.\n\n## Changes\n\n- Add `testTransferZero`\
    \ / `testSendZero` to `Stipends.sol` fixture \u2014 these call `transfer(0)` and\
    \ `send(0)` on EOA, DoNothingReceiver, and SimpleReceiver\n- Add corresponding\
    \ Rust tests that exercise the `AllowNext` path\n- Add trace logs to the call\
    \ stipend match for debugging\n\n## Test plan\n\n- [x] `evm_call_stipends_work_for_transfer_zero`\
    \ passes, logs show `gas_limit=2300` \u2192 `AllowNext`\n- [x] `evm_call_stipends_work_for_send_zero`\
    \ passes, logs show `gas_limit=2300` \u2192 `AllowNext`"
```

**File:** prdoc/stable2603/pr_10166.prdoc (L38-40)
```text
    - Re-entrancy protection now has three modes: no protection, `Strict` protection and `AllowNext`
      - `AllowNext` allows to re-enter the same contract but only for the next frame. This is required to implement reentrancy protection for simple transfers with call stipends
      - For `Strict` protection we set `allows_reentry` of the caller to `false` before the creation of the new frame, for `AllowNext` we to it after the creation
```

**File:** substrate/frame/revive/src/metering/math.rs (L32-39)
```rust
fn determine_call_stipend<T: Config>() -> Weight {
	let gas_weight = <EVMGas as Token<T>>::weight(&EVMGas(CALL_STIPEND));
	let event_weight = <RuntimeCosts as Token<T>>::weight(&RuntimeCosts::DepositEvent {
		num_topic: STIPEND_LOG_TOPICS,
		len: STIPEND_LOG_DATA_LEN,
	});
	gas_weight.saturating_add(event_weight)
}
```

**File:** substrate/frame/revive/src/tests/stipends.rs (L125-143)
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
```

**File:** substrate/frame/revive/fixtures/contracts/Stipends.sol (L1-22)
```text
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DoNothingReceiver
 * @dev Receiver contract 1: empty receive(), does nothing
 */
contract DoNothingReceiver {
    receive() external payable {}
}

/**
 * @title SimpleReceiver
 * @dev Receiver contract 2: emits events
 */
contract SimpleReceiver {
    event Received(address from, uint256 amount);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }
}
```
