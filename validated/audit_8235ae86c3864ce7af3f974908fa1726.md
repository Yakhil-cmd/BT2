No vulnerability found for this question.

**Rationale:** The Sherlock report concerns Solidity's `GovernorBravoDelegate.propose()`, where `targets`, `signatures`, and `calldatas` are raw, untyped byte arrays that get assembled into arbitrary low-level calls at execution time — the vulnerability class is "insufficient validation of raw call encoding before arbitrary execution," which is intrinsic to how Solidity governance contracts work.

This does not map onto FRAME governance pallets. In `pallet-democracy`, `pallet-collective`, and `pallet-referenda`, a "proposal" is not raw bytes/targets/calldata — it is a strongly-typed `RuntimeCall` (or a bounded/hashed preimage of one), e.g. `propose(origin, proposal: BoundedCallOf<T>, ...)` [1](#0-0)  and `propose(origin, threshold, proposal: Box<Proposal>, length_bound)` in the collective pallet [2](#0-1) . The Rust type system and SCALE codec guarantee that a `RuntimeCall` either decodes to a valid, well-formed dispatchable or fails decoding entirely — there is no analog to "malformed calldata" reaching execution, since dispatch always goes through the normal `Dispatchable`/origin-filter machinery (e.g. `frame_system::Config::BaseCallFilter`) rather than an unchecked low-level `call(target, data)`.

Additionally, execution of a passed proposal is gated by call filters and origin checks (seen in tests like `batch_all_doesnt_work_with_inherents` and `CallFiltered` [3](#0-2) ), and FRAME governance intentionally allows arbitrary dispatch of any well-formed `RuntimeCall` once a vote/threshold passes — that is the designed behavior of governance, not a missing validation. There is no attacker-controlled "malicious calldata" path here since only valid, decodable `RuntimeCall` values can ever be submitted or stored as a proposal in the first place.

Given the structural difference (typed dispatch vs. raw bytecode targets), this EVM-specific bug class does not have a demonstrable Polkadot SDK analog, and forcing it onto FRAME per the given instructions is not appropriate.

### Citations

**File:** substrate/frame/democracy/src/lib.rs (L586-591)
```rust
		pub fn propose(
			origin: OriginFor<T>,
			proposal: BoundedCallOf<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let who = T::SubmitOrigin::ensure_origin(origin)?;
```

**File:** substrate/frame/collective/src/lib.rs (L695-703)
```rust
		pub fn propose(
			origin: OriginFor<T>,
			#[pallet::compact] threshold: MemberCount,
			proposal: Box<<T as Config<I>>::Proposal>,
			#[pallet::compact] length_bound: u32,
		) -> DispatchResultWithPostInfo {
			let who = ensure_signed(origin)?;
			let members = Members::<T, I>::get();
			ensure!(members.contains(&who), Error::<T, I>::NotMember);
```

**File:** substrate/frame/utility/src/tests.rs (L814-833)
```rust
#[test]
fn batch_all_doesnt_work_with_inherents() {
	new_test_ext().execute_with(|| {
		let batch_all = RuntimeCall::Utility(UtilityCall::batch_all {
			calls: vec![RuntimeCall::Timestamp(TimestampCall::set { now: 42 })],
		});
		let info = batch_all.get_dispatch_info();

		// fails because inherents expect the origin to be none.
		assert_noop!(
			batch_all.dispatch(RuntimeOrigin::signed(1)),
			DispatchErrorWithPostInfo {
				post_info: PostDispatchInfo {
					actual_weight: Some(info.call_weight),
					pays_fee: Pays::Yes
				},
				error: frame_system::Error::<Test>::CallFiltered.into(),
			}
		);
	})
```
