No vulnerability found for this question.

The reported issue is a Solidity-specific bug: `recipientAddress` is declared but only conditionally assigned across an `if/else` branch, leaving it as the default `address(0)` when `useRegistryAnchor` is true, which then trips a zero-address guard. This class of bug — a variable left uninitialized (defaulting silently) because one branch of a conditional forgot to assign it — is a byproduct of Solidity's permissive "default value" semantics for uninitialized locals.

Rust, which is what FRAME pallets, XCM executor code, and `pallet-revive`/`pallet-contracts` runtime logic are written in, does not allow this bug class to exist in the same form: the Rust compiler enforces "use of possibly-uninitialized variable" as a hard compile error unless every reachable path assigns the variable (or a `Default`/explicit initializer is given at declaration). I searched broadly across the repository for:
- Cross-branch conditional initialization patterns analogous to `useRegistryAnchor` (e.g., registry-anchor-style branching in recipient/registration logic),
- Zero-address/zero-account guard checks that could be bypassed by a default-initialized value,
- Any FRAME dispatchable, XCM barrier/executor, or bridge component where a locally-scoped identifier could remain at its default/zero value due to incomplete branch coverage,

and found no structurally equivalent pattern. Rust code that superficially resembles the two-branch decode-then-validate structure (e.g., `substrate/frame/staking/src/pallet/impls.rs` payee/ledger checks, `substrate/frame/system/src/extensions/check_non_zero_sender.rs`, `pallet-revive`'s EIP-7702 `from`-address validation tests) all rely on values that are either required at declaration, wrapped in `Option`, or explicitly checked by the compiler for initialization on every path — none exhibit an uninitialized-default-value-bypasses-a-later-check flaw reachable via a real signed extrinsic, XCM message, or contract call. [1](#0-0) [2](#0-1) 

Since the vulnerability class requires Solidity's permissive default-value semantics for uninitialized locals — a language feature Rust does not have — there is no demonstrable analog in this Polkadot SDK codebase that meets the required standard of exact file:line evidence plus a real user-entry-point reproduction.

### Citations

**File:** substrate/frame/system/src/extensions/check_non_zero_sender.rs (L29-31)
```rust
/// Check to ensure that the sender is not the zero address.
#[derive(Encode, Decode, DecodeWithMemTracking, DefaultNoBound, Clone, Eq, PartialEq, TypeInfo)]
#[scale_info(skip_type_params(T))]
```

**File:** substrate/frame/revive/src/tests/eip7702.rs (L1387-1420)
```rust
/// A dry run carrying an authorization list but no `from` must be rejected rather than fall back
/// to the zero address. The zero-address account funds nothing, so every authorization would roll
/// back post-validation and be dropped from the estimate — an under-priced estimate that looks
/// valid.
#[test]
fn dry_run_with_authorization_list_requires_from() {
	ExtBuilder::default().build().execute_with(|| {
		let _ = <<Test as Config>::Currency as Mutate<_>>::set_balance(&ALICE, 100_000_000_000);

		let target_contract = builder::bare_instantiate(Code::Upload(dummy_evm_contract()))
			.build_and_unwrap_contract();

		let chain_id = U256::from(<Test as Config>::ChainId::get());
		let signer = TestSigner::new(&[0xAB; 32]);
		let auth = signer.sign_authorization(chain_id, target_contract.addr, U256::zero());

		let result = crate::Pallet::<Test>::dry_run_eth_transact(
			crate::GenericTransaction {
				from: None,
				to: Some(target_contract.addr),
				authorization_list: vec![auth.clone()],
				..Default::default()
			},
			None,
			true,
			None,
		);

		assert!(
			matches!(&result, Err(crate::EthTransactError::Message(msg)) if msg.contains("`from`")),
			"expected a missing-`from` rejection, got: {result:?}"
		);
		// The rejection must happen before any delegation is written.
		assert!(!AccountInfo::<Test>::is_delegated(&signer.address));
```
