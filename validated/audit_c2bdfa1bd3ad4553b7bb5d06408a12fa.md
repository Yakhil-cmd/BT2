### Title
`pallet-collective` blocks re-proposing an identical motion while the first is still active - ([File: substrate/frame/collective/src/lib.rs])

### Summary
`pallet-collective::do_propose_proposed` derives the storage key for an active proposal purely from the encoded call data (`T::Hashing::hash_of(&proposal)`), with no distinguishing nonce, timestamp, or index. If a member proposes the exact same call twice while the first proposal is still open for voting, the second call is rejected with `Error::DuplicateProposal`. This is structurally the same root cause as the referenced `TimeLock.schedule` finding: a content-only hash used as a dedup/identity key prevents legitimate re-submission of the same action until the prior instance is closed.

### Finding Description
`propose` (with `threshold >= 2`) calls `Self::do_propose_proposed`: [1](#0-0) 

```
let proposal_hash = T::Hashing::hash_of(&proposal);
ensure!(!<ProposalOf<T, I>>::contains_key(proposal_hash), Error::<T, I>::DuplicateProposal);
```

The hash is computed solely over the `proposal` bytes (the `RuntimeCall` to be dispatched). `ProposalOf` is only cleared when the proposal is closed via `do_close`, `disapprove_proposal`, or `kill` (which call `remove_proposal(proposal_hash)`), as seen from the extrinsics: [2](#0-1) [3](#0-2) [4](#0-3) 

There is no mechanism (e.g., a proposal index, nonce, or timestamp mixed into the hash) that lets two proposals with identical call data coexist. Any member who is a valid, non-privileged `Signed` member of the collective (`ensure_signed` + `members.contains(&who)` check at line 701-703) can hit this: if they (or another member) submit the exact same `RuntimeCall` twice before the first is closed, the second `propose` call fails deterministically with `DuplicateProposal`, even though there is no economic or governance reason to disallow two independent, concurrently-voted instances of the same action (e.g., two separate "pay contractor X" motions submitted two weeks apart while the first is still pending due to a long `MotionDuration`, or two members independently proposing the same remedial action without realizing it, and wanting a second attempt to run in parallel rather than wait).

This mirrors the audited `TimeLock` bug exactly in mechanism: the identity/dedup key (`txHash` in the original, `proposal_hash` here) is computed only from call content, with no differentiator such as `eta`/index, so a legitimate repeat of the same action is blocked until the earlier instance's lifecycle (`voting period elapses` / `close` / `disapprove` / `kill`) completes.

### Impact Explanation
This is a functional/availability limitation on legitimate collective governance actions, not a fund-theft, unauthorized-dispatch, or issuance bug. Any collective (e.g., Council/Technical Committee instances wired via `pallet_collective::Instance` in `substrate/bin/node/runtime/src/lib.rs`) that needs to re-run an identical action recurringly (e.g., periodic identical remarks, periodic identical parameter-setting calls, or resubmitting an identical proposal after a failed vote count edge case) cannot do so until the first proposal is fully closed, exactly analogous to the reported Yield `TimeLock` Medium-severity finding. No funds are directly at risk, and the workaround (adding a distinguishing byte/marker to the call, or waiting for `MotionDuration`/closing the first proposal) is available to callers, matching the low/medium severity classification of the original report rather than a Critical/High exploit.

### Likelihood Explanation
Likelihood is low-to-moderate: it requires a collective member submitting byte-for-byte identical `RuntimeCall` data twice within the same active-proposal window (i.e., before `MotionDuration` elapses or before `close`/`disapprove_proposal`/`kill` is called). This can realistically occur for recurring/periodic governance actions (e.g., identical treasury spends, identical parameter toggles) or accidental duplicate submissions by different members, similar to the "pay a contractor every 2 weeks but the lock period is 30 days" scenario in the original report.

### Recommendation
Mix a distinguishing value (e.g., the current `ProposalCount`, a block number, or an explicit caller-supplied nonce) into the value used as the `Proposals`/`ProposalOf`/`Voting` storage key, or key proposals by `(proposal_hash, index)` instead of `proposal_hash` alone, so identical call data can be proposed and voted on independently and concurrently, matching the fix pattern the original report recommended (including `eta`/a nonce in the identity hash) and the analogous refactor description mentioned in the report (allowing repeated proposals with the same data).

### Proof of Concept
No live execution was performed (no filesystem/terminal access in this mode). The finding is derived directly from static code inspection of `substrate/frame/collective/src/lib.rs`:
1. Member `A` (a genuine member of `Members::<T, I>`) calls `propose(origin, threshold=2, proposal=X, length_bound)` → succeeds, `ProposalOf` now contains `hash_of(X)` (lines 943-969).
2. Before the proposal is closed/disapproved (`Voting::end` not yet reached and no `close`/`disapprove_proposal`/`kill` called), the same or another member calls `propose(origin, threshold=2, proposal=X, length_bound)` again with the identical `X`.
3. `do_propose_proposed` computes the same `proposal_hash = T::Hashing::hash_of(&X)` and the `ensure!(!<ProposalOf<T, I>>::contains_key(proposal_hash), Error::<T, I>::DuplicateProposal)` check at line 953 fails deterministically, returning `Error::<T, I>::DuplicateProposal` — confirmed by reading the guard directly; this is a pure static-code demonstration (not an executed test run) since no sandbox/terminal was available in this session to run `cargo test` against `pallet-collective`'s existing test suite (`substrate/frame/collective/src/tests.rs`) to add an explicit reproduction. A background Devin session with terminal access would be needed to actually execute a new `#[test]` asserting this sequence returns `Error::<Test, _>::DuplicateProposal`.

### Citations

**File:** substrate/frame/collective/src/lib.rs (L695-728)
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

			if threshold < 2 {
				let (proposal_len, result) = Self::do_propose_execute(proposal, length_bound)?;

				Ok(get_result_weight(result)
					.map(|w| {
						T::WeightInfo::propose_execute(
							proposal_len as u32,  // B
							members.len() as u32, // M
						)
						.saturating_add(w) // P1
					})
					.into())
			} else {
				let (proposal_len, active_proposals) =
					Self::do_propose_proposed(who, threshold, proposal, length_bound)?;

				Ok(Some(T::WeightInfo::propose_proposed(
					proposal_len as u32,  // B
					members.len() as u32, // M
					active_proposals,     // P2
				))
				.into())
			}
		}
```

**File:** substrate/frame/collective/src/lib.rs (L773-833)
```rust
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::disapprove_proposal(T::MaxProposals::get()))]
		pub fn disapprove_proposal(
			origin: OriginFor<T>,
			proposal_hash: T::Hash,
		) -> DispatchResultWithPostInfo {
			T::DisapproveOrigin::ensure_origin(origin)?;
			let proposal_count = Self::do_disapprove_proposal(proposal_hash);
			Ok(Some(T::WeightInfo::disapprove_proposal(proposal_count)).into())
		}

		/// Close a vote that is either approved, disapproved or whose voting period has ended.
		///
		/// May be called by any signed account in order to finish voting and close the proposal.
		///
		/// If called before the end of the voting period it will only close the vote if it is
		/// has enough votes to be approved or disapproved.
		///
		/// If called after the end of the voting period abstentions are counted as rejections
		/// unless there is a prime member set and the prime member cast an approval.
		///
		/// If the close operation completes successfully with disapproval, the transaction fee will
		/// be waived. Otherwise execution of the approved operation will be charged to the caller.
		///
		/// + `proposal_weight_bound`: The maximum amount of weight consumed by executing the closed
		/// proposal.
		/// + `length_bound`: The upper bound for the length of the proposal in storage. Checked via
		/// `storage::read` so it is `size_of::<u32>() == 4` larger than the pure length.
		///
		/// ## Complexity
		/// - `O(B + M + P1 + P2)` where:
		///   - `B` is `proposal` size in bytes (length-fee-bounded)
		///   - `M` is members-count (code- and governance-bounded)
		///   - `P1` is the complexity of `proposal` preimage.
		///   - `P2` is proposal-count (code-bounded)
		#[pallet::call_index(6)]
		#[pallet::weight((
			{
				let b = *length_bound;
				let m = T::MaxMembers::get();
				let p1 = *proposal_weight_bound;
				let p2 = T::MaxProposals::get();
				T::WeightInfo::close_early_approved(b, m, p2)
					.max(T::WeightInfo::close_early_disapproved(m, p2))
					.max(T::WeightInfo::close_approved(b, m, p2))
					.max(T::WeightInfo::close_disapproved(m, p2))
					.saturating_add(p1)
			},
			DispatchClass::Operational
		))]
		pub fn close(
			origin: OriginFor<T>,
			proposal_hash: T::Hash,
			#[pallet::compact] index: ProposalIndex,
			proposal_weight_bound: Weight,
			#[pallet::compact] length_bound: u32,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;

			Self::do_close(proposal_hash, index, proposal_weight_bound, length_bound)
		}
```

**File:** substrate/frame/collective/src/lib.rs (L843-862)
```rust
		#[pallet::weight(T::WeightInfo::kill(1, T::MaxProposals::get()))]
		pub fn kill(origin: OriginFor<T>, proposal_hash: T::Hash) -> DispatchResultWithPostInfo {
			T::KillOrigin::ensure_origin(origin)?;
			ensure!(
				ProposalOf::<T, I>::get(&proposal_hash).is_some(),
				Error::<T, I>::ProposalMissing
			);
			let burned = if let Some((who, cost)) = <CostOf<T, I>>::take(proposal_hash) {
				cost.burn(&who);
				Self::deposit_event(Event::ProposalCostBurned { proposal_hash, who });
				true
			} else {
				false
			};
			let proposal_count = Self::remove_proposal(proposal_hash);

			Self::deposit_event(Event::Killed { proposal_hash });

			Ok(Some(T::WeightInfo::kill(burned as u32, proposal_count)).into())
		}
```

**File:** substrate/frame/collective/src/lib.rs (L952-953)
```rust
		let proposal_hash = T::Hashing::hash_of(&proposal);
		ensure!(!<ProposalOf<T, I>>::contains_key(proposal_hash), Error::<T, I>::DuplicateProposal);
```
