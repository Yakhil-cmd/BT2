No vulnerability found for this question.

The reported issue is a Solidity-level application bug: the `QVBaseStrategy.sol` contract (part of Gitcoin's Allo V2, an external Solidity project, not part of `polkadot-sdk`) lacks a `receive()` function, so calls with `msg.value` revert. This is a property of the specific application contract's code, not a protocol-level defect.

Searching the `polkadot-sdk` repository for an analogous root cause turns up no matching vulnerability class:

- `pallet-revive` (the EVM-compatibility pallet) explicitly treats a call to an address with no associated code as a plain balance transfer, mirroring EVM EOA semantics, rather than requiring a `receive()`-like guard [1](#0-0) .
- For contract-to-contract value transfers, `pallet-revive`/`pallet-contracts` funnel value transfers through `Currency`/balance transfer logic, with dedicated `TransferFailed` return codes when a transfer to a contract or account fails (e.g., due to existential deposit or insufficient balance), rather than depending on the callee implementing a `receive()`-style hook [2](#0-1) .
- The pallet's own `call` dispatchable performs the same transfer/execution logic uniformly for contract accounts, regular accounts and to-be-created accounts, with the ED handled transparently by the runtime rather than by contract-supplied fallback code [3](#0-2) .

There is no FRAME extrinsic, pallet-revive/pallet-contracts call path, or XCM transactor in `polkadot-sdk` whose value-receiving logic depends on a missing "receive function" analog the way a bare Solidity contract does — the SDK's native transfer/dispatch mechanisms don't have this fallback-hook gap, and the underlying report concerns a third-party Solidity contract, not `polkadot-sdk` production code. No demonstrable protocol-level analog exists.

### Citations

**File:** prdoc/stable2412/pr_5664.prdoc (L1-8)
```text
title: Calling an address without associated code is a balance transfer

doc:
  - audience: Runtime Dev
    description: |
     This makes pallet_revive behave like EVM where a balance transfer
     is just a call to a plain wallet.

```

**File:** substrate/frame/revive/src/tests/pvm.rs (L1311-1326)
```rust
#[test]
fn transfer_return_code() {
	let (binary, _code_hash) = compile_module("transfer_return_code").unwrap();
	ExtBuilder::default().existential_deposit(50).build().execute_with(|| {
		let min_balance = Contracts::min_balance();
		let _ = <Test as Config>::Currency::set_balance(&ALICE, 1000 * min_balance);

		let contract = builder::bare_instantiate(Code::Upload(binary))
			.native_value(min_balance * 100)
			.build_and_unwrap_contract();

		// Contract has only the minimal balance so any transfer will fail.
		<Test as Config>::Currency::set_balance(&contract.account_id, min_balance);
		let result = builder::bare_call(contract.addr).build_and_unwrap_result();
		assert_return_code!(result, RuntimeReturnCode::TransferFailed);
	});
```

**File:** substrate/frame/revive/src/lib.rs (L1160-1177)
```rust
		/// Makes a call to an account, optionally transferring some balance.
		///
		/// # Parameters
		///
		/// * `dest`: Address of the contract to call.
		/// * `value`: The balance to transfer from the `origin` to `dest`.
		/// * `weight_limit`: The weight limit enforced when executing the constructor.
		/// * `storage_deposit_limit`: The maximum amount of balance that can be charged from the
		///   caller to pay for the storage consumed.
		/// * `data`: The input data to pass to the contract.
		///
		/// * If the account is a smart-contract account, the associated code will be
		/// executed and any value will be transferred.
		/// * If the account is a regular account, any value will be transferred.
		/// * If no account exists and the call value is not less than `existential_deposit`,
		/// a regular account will be created and any value will be transferred.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as Config>::WeightInfo::call().saturating_add(*weight_limit))]
```
