## Analog Found: Stale Vote Weight Persists in `pallet-ranked-collective` After Member Demotion/Removal

### Title
Ranked-collective member demotion/removal does not adjust already-cast vote weight in ongoing poll tallies, letting stale votes influence referendum outcomes - (File: `substrate/frame/ranked-collective/src/lib.rs`)

### Summary
`pallet-ranked-collective` implements the `Tally`/`VoteTally` used by `pallet-referenda` for ranked polls (e.g. Fellowship referenda). When a member votes, their rank-weighted vote is immediately accrued into the poll's `Tally` (`bare_ayes`, `ayes`, `nays`), which is stored inside the *poll* (owned by `T::Polls`, i.e. `pallet-referenda`'s `ReferendumInfoFor`), separately from the pallet's own `Voting` map. `do_demote_member` and `do_remove_member_from_rank` only mutate membership bookkeeping (`Members`, `IdToIndex`, `IndexToId`, `MemberCount`) — they never touch ongoing polls' tallies or the member's prior `Voting` entry. This is the same class of bug described in the report: votes cast by an account are still counted toward quorum/approval after that account is no longer eligible (removed or demoted below the poll's `min_rank`).

### Finding Description
The vote flow accrues weight directly into the tally at vote time: [1](#0-0) 

Weight is computed from the *current* rank at the moment of voting (`Self::rank_to_votes(record.rank, min_rank)`), and stored in `Voting::<T,I>` plus accrued into `tally.ayes`/`tally.bare_ayes`/`tally.nays`.

Membership removal/demotion never revisits this tally: [2](#0-1) [3](#0-2) 

Neither `remove_from_rank` (index bookkeeping only) nor `do_remove_member_from_rank`/`do_demote_member` iterate over ongoing polls or adjust `Voting`/`Tally` state. Contrast this with `pallet-collective`, which explicitly filters removed accounts out of `ayes`/`nays` on membership change: [4](#0-3) 
(tested at `removal_of_old_voters_votes_works`, [5](#0-4) ).

`pallet-ranked-collective` has no equivalent mechanism for *ongoing* polls. `cleanup_poll` only removes `Voting` entries for *completed* polls (post-decision, so harmless to the tally): [6](#0-5) 

The `Tally::support` denominator is computed live via `M::get_max_voters(class)` (i.e. current member count), while the numerator (`bare_ayes`/`ayes`) still includes weight from members who have since been demoted or removed: [7](#0-6) 

### Impact Explanation
A ranked/Fellowship referendum's approval and support calculations (consumed by `pallet-referenda` each time it services the poll) can remain influenced by an account that is no longer a member, or whose rank has been lowered below the poll's `min_rank`, or above the max allowed. Since numerator (`ayes`/`bare_ayes`) isn't corrected while denominator (`max_voters`) shrinks with membership changes, support/approval percentages become inconsistent with the *current* electorate, potentially causing a referendum to pass or stay above threshold using votes that should no longer count — mirroring the reported "premature quorum from removed voters" bug class. This is an integrity break in on-chain governance decision-making rather than a direct fund-theft primitive, so it is best characterized as Medium severity (stale/incorrect governance-tally state, not unauthorized dispatch by itself, though it can ultimately let an unauthorized-composition tally *approve* privileged referendum-only dispatches).

### Likelihood Explanation
No privileged role is required by the "attacker" — a rank-holding member simply votes on an ongoing poll through the standard `vote` extrinsic (its own normal signed transaction), and is later independently demoted or removed via a routine governance action (e.g. Fellowship attrition/`demote_member`/`remove_member`, both plausible and expected operations in the Fellowship/Ambassador workflow). No collusion or malicious removal is needed — normal fellowship housekeeping (demoting inactive members) triggers the stale-vote condition on any poll that member voted on before being demoted/removed. This makes the scenario readily reachable in the intended, deployed configuration (e.g. Collectives parachain Fellowship referenda).

### Recommendation
When a member's rank changes (`do_promote_member`, `do_demote_member`) or they are removed (`do_remove_member_from_rank`), the pallet should either: (1) walk ongoing polls the account has voted in (tracked similarly to how `pallet-collective` tracks proposals) and adjust/rescind the vote's contribution to `Tally`, or (2) recompute vote weight lazily against current rank at poll-resolution time rather than at vote-cast time, or (3) expose a `T::Polls` hook to renormalize/expire the vote when membership changes, analogous to `ChangeMembers::change_members_sorted`'s cleanup in `pallet-collective`.

### Proof of Concept
No executable PoC was run (ask-only mode; no execution against real state); the trace above is a static-analysis confirmation:
1. Member `A` at rank `R` calls `vote(poll, true)` → `tally.ayes += votes(R)`, `tally.bare_ayes += 1`, `Voting::insert(poll, A, Aye(votes(R)))` (`substrate/frame/ranked-collective/src/lib.rs:638-682`).
2. Governance later calls `demote_member(A)` or `remove_member(A, rank)` — neither touches `Voting::<T,I>::get(poll, A)` nor the poll's live `Tally` (`substrate/frame/ranked-collective/src/lib.rs:842-899`).
3. `pallet-referenda` continues to service the still-ongoing poll using the unmodified `Tally`, whose `ayes`/`bare_ayes` still include `A`'s vote weight, while `M::get_max_voters(class)` reflects the reduced membership — an existing unit test (`voting_works`, `substrate/frame/ranked-collective/src/tests.rs:402-434`) confirms tally accrual semantics but there is no companion test asserting tally correction on `demote_member`/`remove_member`, unlike the explicit `removal_of_old_voters_votes_works` test that exists for `pallet-collective`.

This is a static/code-inspection finding (guards checked: `ensure_member`, `RemoveOrigin`, `DemoteOrigin`, `MinRankOfClass` — none of which reference or clean `Voting`/`Tally` state on removal); no live test execution was performed against a running node in this session.

### Citations

**File:** substrate/frame/ranked-collective/src/lib.rs (L122-138)
```rust
impl<T: Config<I>, I: 'static, M: GetMaxVoters<Class = ClassOf<T, I>>>
	VoteTally<Votes, ClassOf<T, I>> for Tally<T, I, M>
{
	fn new(_: ClassOf<T, I>) -> Self {
		Self { bare_ayes: 0, ayes: 0, nays: 0, dummy: PhantomData }
	}
	fn ayes(&self, _: ClassOf<T, I>) -> Votes {
		self.bare_ayes
	}
	fn support(&self, class: ClassOf<T, I>) -> Perbill {
		Perbill::from_rational(self.bare_ayes, M::get_max_voters(class))
	}
	fn approval(&self, _: ClassOf<T, I>) -> Perbill {
		// Both fields accrue saturatingly, so their sum can exceed `Votes`.
		let (ayes, nays) = (u64::from(self.ayes), u64::from(self.nays));
		Perbill::from_rational(ayes, 1.max(ayes + nays))
	}
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L648-676)
```rust
			let (tally, vote) = T::Polls::try_access_poll(
				poll,
				|mut status| -> Result<(TallyOf<T, I>, VoteRecord), DispatchError> {
					match status {
						PollStatus::None | PollStatus::Completed(..) => {
							Err(Error::<T, I>::NotPolling)?
						},
						PollStatus::Ongoing(ref mut tally, class) => {
							match Voting::<T, I>::get(&poll, &who) {
								Some(Aye(votes)) => {
									tally.bare_ayes.saturating_dec();
									tally.ayes.saturating_reduce(votes);
								},
								Some(Nay(votes)) => tally.nays.saturating_reduce(votes),
								None => pays = Pays::No,
							}
							let min_rank = T::MinRankOfClass::convert(class);
							let votes = Self::rank_to_votes(record.rank, min_rank)?;
							let vote = VoteRecord::from((aye, votes));
							match aye {
								true => {
									tally.bare_ayes.saturating_inc();
									tally.ayes.saturating_accrue(votes);
								},
								false => tally.nays.saturating_accrue(votes),
							}
							Voting::<T, I>::insert(&poll, &who, &vote);
							Ok((tally.clone(), vote))
						},
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L694-719)
```rust
		#[pallet::call_index(5)]
		#[pallet::weight(T::WeightInfo::cleanup_poll(*max))]
		pub fn cleanup_poll(
			origin: OriginFor<T>,
			poll_index: PollIndexOf<T, I>,
			max: u32,
		) -> DispatchResultWithPostInfo {
			ensure_signed(origin)?;
			ensure!(T::Polls::as_ongoing(poll_index).is_none(), Error::<T, I>::Ongoing);

			let r = Voting::<T, I>::clear_prefix(
				poll_index,
				max,
				VotingCleanup::<T, I>::take(poll_index).as_ref().map(|c| &c[..]),
			);
			if r.unique == 0 {
				// return Err(Error::<T, I>::NoneRemaining)
				return Ok(Pays::Yes.into());
			}
			if let Some(cursor) = r.maybe_cursor {
				VotingCleanup::<T, I>::insert(poll_index, BoundedVec::truncate_from(cursor));
			}
			Ok(PostDispatchInfo {
				actual_weight: Some(T::WeightInfo::cleanup_poll(r.unique)),
				pays_fee: Pays::No,
			})
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L842-867)
```rust
		/// Demotes a member in the ranked collective into the next lower rank.
		///
		/// A `maybe_max_rank` may be provided to check that the member does not get demoted from
		/// a certain rank. Is `None` is provided, then the rank will be decremented without checks.
		fn do_demote_member(who: T::AccountId, maybe_max_rank: Option<Rank>) -> DispatchResult {
			let mut record = Self::ensure_member(&who)?;
			let rank = record.rank;
			if let Some(max_rank) = maybe_max_rank {
				ensure!(max_rank >= rank, Error::<T, I>::NoPermission);
			}

			Self::remove_from_rank(&who, rank)?;
			let maybe_rank = rank.checked_sub(1);
			match maybe_rank {
				None => {
					Members::<T, I>::remove(&who);
					Self::deposit_event(Event::MemberRemoved { who, rank: 0 });
				},
				Some(rank) => {
					record.rank = rank;
					Members::<T, I>::insert(&who, &record);
					Self::deposit_event(Event::RankChanged { who, rank });
				},
			}
			Ok(())
		}
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L892-899)
```rust
		/// Removes a member from the rank collective
		pub fn do_remove_member_from_rank(who: &T::AccountId, rank: Rank) -> DispatchResult {
			for r in 0..=rank {
				Self::remove_from_rank(&who, r)?;
			}
			Members::<T, I>::remove(&who);
			Ok(())
		}
```

**File:** substrate/frame/collective/src/lib.rs (L1325-1344)
```rust
		// remove accounts from all current voting in motions.
		let mut outgoing = outgoing.to_vec();
		outgoing.sort();
		for h in Proposals::<T, I>::get().into_iter() {
			<Voting<T, I>>::mutate(h, |v| {
				if let Some(mut votes) = v.take() {
					votes.ayes = votes
						.ayes
						.into_iter()
						.filter(|i| outgoing.binary_search(i).is_err())
						.collect();
					votes.nays = votes
						.nays
						.into_iter()
						.filter(|i| outgoing.binary_search(i).is_err())
						.collect();
					*v = Some(votes);
				}
			});
		}
```

**File:** substrate/frame/collective/src/tests.rs (L730-776)
```rust
#[test]
fn removal_of_old_voters_votes_works() {
	ExtBuilder::default().build_and_execute(|| {
		let proposal = make_proposal(42);
		let proposal_len: u32 = proposal.using_encoded(|p| p.len() as u32);
		let hash = BlakeTwo256::hash_of(&proposal);
		let end = 4;
		assert_ok!(Collective::propose(
			RuntimeOrigin::signed(1),
			3,
			Box::new(proposal.clone()),
			proposal_len
		));
		assert_ok!(Collective::vote(RuntimeOrigin::signed(1), hash, 0, true));
		assert_ok!(Collective::vote(RuntimeOrigin::signed(2), hash, 0, true));
		assert_eq!(
			Voting::<Test, Instance1>::get(&hash),
			Some(Votes { index: 0, threshold: 3, ayes: vec![1, 2], nays: vec![], end })
		);
		Collective::change_members_sorted(&[4], &[1], &[2, 3, 4]);
		assert_eq!(
			Voting::<Test, Instance1>::get(&hash),
			Some(Votes { index: 0, threshold: 3, ayes: vec![2], nays: vec![], end })
		);

		let proposal = make_proposal(69);
		let proposal_len: u32 = proposal.using_encoded(|p| p.len() as u32);
		let hash = BlakeTwo256::hash_of(&proposal);
		assert_ok!(Collective::propose(
			RuntimeOrigin::signed(2),
			2,
			Box::new(proposal.clone()),
			proposal_len
		));
		assert_ok!(Collective::vote(RuntimeOrigin::signed(2), hash, 1, true));
		assert_ok!(Collective::vote(RuntimeOrigin::signed(3), hash, 1, false));
		assert_eq!(
			Voting::<Test, Instance1>::get(&hash),
			Some(Votes { index: 1, threshold: 2, ayes: vec![2], nays: vec![3], end })
		);
		Collective::change_members_sorted(&[], &[3], &[2, 4]);
		assert_eq!(
			Voting::<Test, Instance1>::get(&hash),
			Some(Votes { index: 1, threshold: 2, ayes: vec![2], nays: vec![], end })
		);
	});
}
```
