### Title
`callerIsOrigin()`/`caller_is_origin()` no longer implies "caller is a plain, non-programmable account" once EIP-7702 account delegation is enabled - ([File: substrate/frame/revive/src/exec.rs])

### Summary
The external report describes the generic `onlyEOA()` / `tx.origin == msg.sender` anti-flash-loan/anti-sandwich pattern being invalidated once an EOA can delegate control to smart-contract logic (EIP-3074). `pallet-revive` exposes the exact same pattern as a first-class primitive, `caller_is_origin()` / `Ext::callerIsOrigin()`, which is explicitly documented as the way for a contract to distinguish "a plain account" from "a contract" caller [1](#0-0) . `pallet-revive` has since implemented EIP-7702 account delegation, which lets a signed EOA delegate its address to run arbitrary contract code while keeping its own account identity [2](#0-1) . Because delegated-EOA execution preserves the EOA's account identity for both `caller()` and `origin()`, any contract that relies on `caller_is_origin()`/`callerIsOrigin()` to gate against composable/atomic attacker logic no longer gets the guarantee it is documented to provide.

### Finding Description
`caller_is_origin` is implemented purely as an address-identity comparison, `self.origin == caller`, with no notion of whether that address currently has delegated code attached to it: [3](#0-2) 

The Solidity-facing documentation for this primitive explicitly recommends it as the way to tell a "plain account" apart from a contract caller, i.e. the on-chain equivalent of `onlyEOA()`: [1](#0-0) 

`pallet-revive`'s EIP-7702 implementation lets any EOA sign an `AuthorizationListEntry` that sets a `delegate_target` contract for its own address; subsequent calls that reach that address execute the target contract's code while using the EOA's own storage and balance: [4](#0-3) 

Crucially, `ensure_non_contract_if_signed` (the pallet's EIP-3607 "is this origin a contract" guard, functionally identical to `onlyEOA()`) is explicitly designed to keep treating a delegated EOA as a non-contract, allowed origin: [5](#0-4) [6](#0-5) 

Consequently, an attacker-controlled EOA `X` can:
1. Sign a 7702 authorization delegating `X` to attacker contract `Y` (permissionless, no privileged role required).
2. Submit a top-level transaction with `to = X` (a "self-call"), which loads `Y`'s bytecode but runs it under `X`'s own account/storage/balance identity, per the documented execution model ("On a call to a delegated EOA the runtime loads the target contract's code but uses the EOA's own storage and balance") [7](#0-6) .
3. Inside that delegated execution, `X`'s (i.e. `Y`'s) code performs arbitrary multi-step, atomic contract logic (equivalent of flash-borrow, price manipulation, sandwich construction, etc.) and then calls into victim contract `Z`.
4. From `Z`'s perspective, the direct caller and the stack origin are both `X`, so `Z`'s `callerIsOrigin()`/`caller_is_origin()` check reports `true` - exactly as if `X` had made an ordinary, non-programmable call - even though `X` just executed arbitrary attacker-supplied contract logic in the same atomic transaction before reaching `Z`.

This is a faithful FRAME/pallet-revive analog of the EIP-3074 concern in the report: the invariant "caller is EOA ⇒ caller could not have run arbitrary composable contract logic in this transaction" is broken by account delegation, while the check itself (`caller_is_origin`/`callerIsOrigin`) still returns the value that downstream contracts interpret as "safe, not a contract-driven attack."

### Impact Explanation
Any Solidity contract deployed on `pallet-revive` that uses `callerIsOrigin()` (or the underlying `caller_is_origin` host function) as its `onlyEOA()`-style guard against flash-loan/sandwich composability loses that protection once EIP-7702 delegation is live for the chain. This is the same class of impact as the original report: bypass of a caller-controlled security assumption, enabling flash-loan/sandwich-style attacks that the guard was meant to prevent. The severity depends entirely on what a specific downstream contract protects with this check (this is a platform-level primitive, not itself a fund-loss bug in `pallet-revive`), which is why the original report is rated Medium rather than Critical/High.

### Likelihood Explanation
- No privileged role, governance, or stolen keys are required: any EOA can self-authorize a 7702 delegation and call itself.
- `ensure_non_contract_if_signed`/EIP-3607 checks are explicitly designed to still allow delegated EOAs as signed origins, so there is no gate preventing this pattern [6](#0-5) .
- Exploitability depends on (a) the chain having EIP-7702 delegation enabled (a `pallet-revive` feature, not yet necessarily deployed to production runtimes at time of writing) and (b) a downstream Solidity/PVM contract actually relying on `callerIsOrigin()`/`caller_is_origin()` as its sole anti-composability guard. I was not able to find, and did not attempt to invent, such a downstream contract inside the polkadot-sdk repository itself (the primitive is generic runtime infrastructure, consumed by external contracts, not by any in-repo pallet that itself needs flash-loan protection).

### Recommendation
- Document explicitly (in the `caller_is_origin`/`callerIsOrigin` host-function docs and in the EIP-7702 PR docs) that once account delegation is enabled, `caller_is_origin() == true` no longer implies the caller could not have executed arbitrary composable logic in the same transaction, mirroring the same caveat Ethereum client teams give for EIP-3074/7702 versus `tx.origin == msg.sender`.
- Consider exposing a host function that reports whether the origin/caller address currently has an active delegation (`AccountInfo::is_delegated`), so contract authors who need the stricter "no delegated code could have run" guarantee have a way to check it, rather than relying on `callerIsOrigin()` alone.

### Proof of Concept
I could not build and execute a concrete Rust/FRAME integration test within the available tools (no filesystem/terminal access in this session), so no PoC was run and no test output can be reported. The reachability chain is nonetheless demonstrated purely from in-repo evidence:
- `AuthorizationListEntry`/`process_authorizations` lets any signer delegate their own EOA address to a contract (`substrate/frame/revive/src/tests/eip7702.rs`, `prdoc/pr_12229.prdoc`).
- `ensure_non_contract_if_signed` (`substrate/frame/revive/src/lib.rs:2945-2970`) and its test `eip3607_checks` (`substrate/frame/revive/src/tests/eip7702.rs:168-189`) confirm a delegated EOA still passes the "not a contract" origin check.
- `caller_is_origin`'s address-identity-only implementation (`substrate/frame/revive/src/exec.rs:2505-2508`) confirms it cannot distinguish "plain EOA call" from "EOA self-call executing delegated contract code."

Given the uncertainty about whether any current in-repo/production runtime actually enables EIP-7702 and ships a contract that relies on `callerIsOrigin()` for flash-loan protection, and given I could not execute a reproduction, I present this as a supported architectural analog rather than a confirmed exploited instance.

### Citations

**File:** substrate/frame/contracts/uapi/src/host.rs (L253-263)
```rust
	/// Checks whether the caller of the current contract is the origin of the whole call stack.
	///
	/// Prefer this over [`is_contract()`][`Self::is_contract`] when checking whether your contract
	/// is being called by a contract or a plain account. The reason is that it performs better
	/// since it does not need to do any storage lookups.
	///
	/// # Return
	///
	/// A return value of `true` indicates that this contract is being called by a plain account
	/// and `false` indicates that the caller is another contract.
	fn caller_is_origin() -> bool;
```

**File:** prdoc/pr_12229.prdoc (L1-45)
```text
title: '[pallet-revive] EIP-7702 (continued)'
doc:
- audience: Runtime Dev
  description: |
    Continuation of #10936.

    Implements [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) for `pallet-revive`: an EOA can sign an authorization that designates a target contract whose code runs when the EOA is called, while keeping the EOA's storage and balance.

    ## Pallet integration

    `eth_call` gains an `authorization_list: Vec<AuthorizationListEntry>` parameter. The signature change is safe because `eth_call` is never dispatched directly — it's the inner call of `eth_transact`, signed by an Ethereum wallet and submitted via `eth-rpc`. List length is bounded indirectly: each entry reserves `worst_case_delegation_deposit` against the tx's storage-deposit budget, so a transaction can only carry as many entries as its budget covers.

    ## Authorization processing

    `process_authorizations` runs **before** the call. It validates each entry (chain ID, signature, nonce, account type), creates the authority account if needed, and sets or clears the delegation. Two key semantics:

    - Per-entry failures (bad chain_id, nonce mismatch, signature recovery, contract-account authority) are silently skipped per spec, so the function as a whole is structurally infallible.
    - Delegation changes persist even if the subsequent call reverts — processing happens outside the call's storage transaction.

    Revive-specific costs per authorization, beyond the EVM baseline:

    - **ED for new accounts**: an authority that didn't exist on-chain is created.
    - **Account-entry deposit**: the `DelegatedEOA` entry persists for the life of the account, so the item/byte cost of its `ContractInfo` is charged on first delegation — even when the target is not a contract — and stays held after clearing. There is no release path: a delegated EOA cannot be terminated, so this deposit is locked permanently once an account has ever been delegated. On a relayed set/clear the recorded payer is refunded in full and the relayer is charged the entry deposit anew (becoming the recorded payer) — relaying a revocation is therefore no longer deposit-neutral for the relayer.
    - **Code lockup deposit + refcount**: delegating to a contract increments the refcount on its code hash so the code can't be deleted while delegated, and reserves a deposit equal to the lockup share of the code's storage cost. Deposits are tracked against the relayer that paid them (see `payer` below) so refunds flow to the original payer regardless of who relays the next set/clear.

    ## Storage changes

    New `AccountType::DelegatedEOA` variant:

    - `delegate_target: Option<H160>` — target contract (`None` after clearing).
    - `contract_info: ContractInfo` — child trie + base-deposit accounting for the delegated EOA.
    - `payer: Option<T::AccountId>` — account that paid the currently held deposit; read on clear/re-delegation so refunds flow back to the original payer rather than whoever relays the next authorization.

    Lifecycle:

    - Once delegated, an EOA stays `DelegatedEOA` permanently; clearing only zeroes the target.
    - The child trie survives across target changes (re-delegate keeps storage).
    - Code refcounts are managed on set/clear.
    - Clearing refunds the code-lockup share of `storage_base_deposit`; the account entry's own deposit stays held — permanently, since the entry persists and delegated accounts cannot be terminated. Per-item storage deposits stay locked until the user re-delegates to a contract that lets them release the items through normal storage operations.

    New error variant: `Error::CannotTerminateDelegatedAccount = 0x44` — `seal_terminate` invoked on a delegated EOA; delegated accounts cannot be torn down via the contract-termination path.

    ## Execution changes

    On a call to a delegated EOA the runtime loads the target contract's code but uses the EOA's own storage and balance. Constructors skip delegation resolution (cannot deploy via a delegated EOA). Delegation is resolved **at most once** — no chain following (if A → B → C, calling A executes B's code; B's own delegation is ignored, and if B is itself delegated the call traps on the `0xef` indicator: nested callers observe a failed subcall (`CalleeTrapped`), a top-level call fails with `ContractTrapped`).
```

**File:** substrate/frame/revive/src/exec.rs (L2505-2508)
```rust
	fn caller_is_origin(&self, use_caller_of_caller: bool) -> bool {
		let caller = if use_caller_of_caller { self.caller_of_caller() } else { self.caller() };
		self.origin == caller
	}
```

**File:** substrate/frame/revive/src/lib.rs (L2945-2970)
```rust
	/// Ensure that the origin is neither a pre-compile nor a contract.
	///
	/// This enforces EIP-3607.
	fn ensure_non_contract_if_signed(origin: &OriginFor<T>) -> DispatchResult {
		if DebugSettings::bypass_eip_3607::<T>() {
			return Ok(());
		}
		let Some(address) = origin
			.as_system_ref()
			.and_then(|o| o.as_signed())
			.map(<T::AddressMapper as AddressMapper<T>>::to_address)
		else {
			return Ok(());
		};
		if exec::is_precompile::<T, ContractBlob<T>>(&address) ||
			<AccountInfo<T>>::is_contract(&address)
		{
			log::debug!(
				target: crate::LOG_TARGET,
				"EIP-3607: reject tx as pre-compile or account exist at {address:?}",
			);
			Err(DispatchError::BadOrigin)
		} else {
			Ok(())
		}
	}
```

**File:** substrate/frame/revive/src/tests/eip7702.rs (L168-189)
```rust
#[test]
fn eip3607_checks() {
	ExtBuilder::default().build().execute_with(|| {
		let _ = <<Test as Config>::Currency as Mutate<_>>::set_balance(&ALICE, 1_000_000_000);

		// Delegated EOAs are allowed to originate transactions
		let authority = H160::from([0x11; 20]);
		let authority_id = <Test as Config>::AddressMapper::to_account_id(&authority);
		let _ = <<Test as Config>::Currency as Mutate<_>>::set_balance(&authority_id, 1_000_000);
		AccountInfo::<Test>::set_delegation(&authority, Some(H160::from([0x22; 20])), &ALICE)
			.unwrap();
		assert_ok!(Contracts::ensure_non_contract_if_signed(&RuntimeOrigin::signed(authority_id)));

		// Regular contracts are rejected
		let Contract { account_id, .. } =
			builder::bare_instantiate(Code::Upload(dummy_evm_contract()))
				.build_and_unwrap_contract();
		assert!(
			Contracts::ensure_non_contract_if_signed(&RuntimeOrigin::signed(account_id)).is_err()
		);
	});
}
```
