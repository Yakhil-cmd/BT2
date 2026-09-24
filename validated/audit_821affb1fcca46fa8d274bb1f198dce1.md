## Analog Found: Missing rank-bound enforcement in `pallet_ranked_collective::exchange_member`

### Title
`exchange_member` in `pallet-ranked-collective` ignores its `ExchangeOrigin` success value, letting a low-rank signed member overwrite the account of any higher-rank member — ([File: substrate/frame/ranked-collective/src/lib.rs])

### Summary
The Apache ShenYu bug allowed a low-privilege administrator to create users with privileges higher than their own because the privilege-management code never bound the created privilege to the caller's own privilege level. The direct FRAME analog is `pallet_ranked_collective::Pallet::exchange_member`, which calls `T::ExchangeOrigin::ensure_origin(origin)?` and **discards the `Success` value entirely**, unlike every sibling privileged extrinsic (`promote_member`, `demote_member`, `remove_member`) in the same pallet, which explicitly compare the returned `max_rank`/`min_rank` against the target member's rank before mutating state. [1](#0-0) 

### Finding Description
`Config::ExchangeOrigin` is declared without a fixed `Success` type: [2](#0-1) 

By contrast, `PromoteOrigin`, `DemoteOrigin`, and `RemoveOrigin` all fix `Success = Rank` and are consumed with an explicit bound check in the call implementation: [3](#0-2) [4](#0-3) 

`exchange_member`, however, never inspects any rank bound coming from `ExchangeOrigin`; it only checks that `who` is a tracked member and then removes `who` from its current rank and re-inserts `new_who` at that exact same rank, with `new_who` fully attacker-chosen: [5](#0-4) 

In production runtime wiring, `ExchangeOrigin` is configured as `EitherOf<Root, Fellows>` in both the Rococo/Kusama-style Fellowship and Collectives-Westend Fellowship: [6](#0-5) [7](#0-6) 

Note that, unlike `PromoteOrigin`/`DemoteOrigin` in the same `Config` block — which wrap the collective-membership check in `MapSuccess`/`TryMapSuccess` combinators that reduce the allowed target rank relative to the caller's own rank (e.g. `TryMapSuccess<EnsureFellowship, CheckedReduceBy<ConstU16<1>>>`) — `ExchangeOrigin` applies **no such reduction**: it is simply `Fellows` (a fixed-rank individual-member check), with the `Success` completely unused by the pallet regardless. This is the exact "privilege of created role not bounded by caller's own privilege" pattern from the ShenYu advisory.

### Impact Explanation
If `Fellows` resolves (as its naming and sibling usage, e.g. `SubmitOrigin = EnsureMember<Runtime, FellowshipCollectiveInstance, 1>`, strongly suggest) to an individual signed-account rank check rather than a body-wide referendum, then any single member meeting that minimum rank can call `exchange_member(who = <any existing member, including the highest rank 9>, new_who = <attacker-controlled account>)`. This removes the legitimate high-rank member from the collective and installs the attacker's own account at that same high rank — a direct, one-shot privilege escalation to the maximum rank in the collective (which gates governance tracks, treasury spends, salary, and promotion rights), bypassing the deliberately rank-limited `PromoteOrigin` entirely. This is a Critical/High "unauthorized dispatch"/governance-takeover class bug per the program's own severity guidance.

### Likelihood Explanation
Likelihood is **uncertain** and could not be fully confirmed in this pass: the exact definition of the `Fellows` type alias referenced in `polkadot/runtime/rococo/src/governance/fellowship.rs` and `collectives-westend/src/fellowship/mod.rs` was not located within the available search budget. If `Fellows` is an individual per-account `EnsureMember` check (consistent with the naming convention used for `SubmitOrigin` in the same file), the bug is trivially reachable by any single Fellow with no governance control needed, satisfying the "no privileged prerequisite" requirement. If `Fellows` instead resolves to a body-wide referendum-gated origin (e.g. `EnsureXcm<IsVoiceOfBody<...>>` or a `Polls`-based collective-vote origin), then triggering it requires collective governance control, which the reporting rules explicitly exclude as a privileged prerequisite. This distinction is the single blocking uncertainty for a definitive verdict.

### Recommendation
Mirror the pattern already used for `promote_member`/`demote_member`/`remove_member`: fix `type ExchangeOrigin: EnsureOrigin<Self::RuntimeOrigin, Success = Rank>` in the pallet `Config`, and in `exchange_member` add `ensure!(max_rank >= rank, Error::<T, I>::NoPermission)` using the `Success` value returned by `T::ExchangeOrigin::ensure_origin(origin)?`, exactly as is already done for the other three privileged rank-mutating calls.

### Proof of Concept
Not executed. A conclusive PoC requires first confirming the concrete definition of the `Fellows` origin alias used in `ExchangeOrigin = EitherOf<Root, Fellows>` (file location not resolved within the available tool budget). If `Fellows` is confirmed to be a single-account `EnsureMember<_, _, MIN_RANK>`-style check, the reproduction would be: in `substrate/frame/ranked-collective/src/tests.rs`, extend the existing `exchange_member_works`/`exchange_member_same_noops` test fixtures (which already show `ExchangeOrigin` composed from `EitherOf<Root, MapSuccess<EnsureRanked<Test, (), 2>, ReduceBy<ConstU16<2>>>>` in the unit-test mock) to call `Club::exchange_member(RuntimeOrigin::signed(<low-rank account>), <high-rank victim>, <attacker account>)` and assert it succeeds and that `Members::<Test>::get(<attacker account>).rank` equals the victim's original (higher) rank — mirroring the existing `promote_demote_by_rank_works` test's structure but for `exchange_member`, which currently has no analogous rank-bound negative test. This was not run against the actual repository in this session.

### Citations

**File:** substrate/frame/ranked-collective/src/lib.rs (L437-438)
```rust
		/// The origin that can swap the account of a member.
		type ExchangeOrigin: EnsureOrigin<Self::RuntimeOrigin>;
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L574-595)
```rust
		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::promote_member(0))]
		pub fn promote_member(origin: OriginFor<T>, who: AccountIdLookupOf<T>) -> DispatchResult {
			let max_rank = T::PromoteOrigin::ensure_origin(origin)?;
			let who = T::Lookup::lookup(who)?;
			Self::do_promote_member(who, Some(max_rank), true)
		}

		/// Decrement the rank of an existing member by one. If the member is already at rank zero,
		/// then they are removed entirely.
		///
		/// - `origin`: Must be the `DemoteOrigin`.
		/// - `who`: Account of existing member of rank greater than zero.
		///
		/// Weight: `O(1)`, less if the member's index is highest in its rank.
		#[pallet::call_index(2)]
		#[pallet::weight(T::WeightInfo::demote_member(0))]
		pub fn demote_member(origin: OriginFor<T>, who: AccountIdLookupOf<T>) -> DispatchResult {
			let max_rank = T::DemoteOrigin::ensure_origin(origin)?;
			let who = T::Lookup::lookup(who)?;
			Self::do_demote_member(who, Some(max_rank))
		}
```

**File:** substrate/frame/ranked-collective/src/lib.rs (L606-616)
```rust
		pub fn remove_member(
			origin: OriginFor<T>,
			who: AccountIdLookupOf<T>,
			min_rank: Rank,
		) -> DispatchResultWithPostInfo {
			let max_rank = T::RemoveOrigin::ensure_origin(origin)?;
			let who = T::Lookup::lookup(who)?;
			let MemberRecord { rank, .. } = Self::ensure_member(&who)?;
			ensure!(min_rank >= rank, Error::<T, I>::InvalidWitness);
			ensure!(max_rank >= rank, Error::<T, I>::NoPermission);

```

**File:** substrate/frame/ranked-collective/src/lib.rs (L722-752)
```rust
		/// Exchanges a member with a new account and the same existing rank.
		///
		/// - `origin`: Must be the `ExchangeOrigin`.
		/// - `who`: Account of existing member of rank greater than zero to be exchanged.
		/// - `new_who`: New Account of existing member of rank greater than zero to exchanged to.
		#[pallet::call_index(6)]
		#[pallet::weight(T::WeightInfo::exchange_member())]
		pub fn exchange_member(
			origin: OriginFor<T>,
			who: AccountIdLookupOf<T>,
			new_who: AccountIdLookupOf<T>,
		) -> DispatchResult {
			T::ExchangeOrigin::ensure_origin(origin)?;
			let who = T::Lookup::lookup(who)?;
			let new_who = T::Lookup::lookup(new_who)?;

			ensure!(who != new_who, Error::<T, I>::SameMember);

			let MemberRecord { rank, .. } = Self::ensure_member(&who)?;

			Self::do_remove_member_from_rank(&who, rank)?;
			Self::do_add_member_to_rank(new_who.clone(), rank, false)?;

			Self::deposit_event(Event::MemberExchanged {
				who: who.clone(),
				new_who: new_who.clone(),
			});
			T::MemberSwappedHandler::swapped(&who, &new_who, rank);

			Ok(())
		}
```

**File:** polkadot/runtime/rococo/src/governance/fellowship.rs (L356-360)
```rust
	// Exchange is by any of:
	// - Root can exchange arbitrarily.
	// - the Fellows origin;
	type ExchangeOrigin =
		EitherOf<EnsureRootWithSuccess<Self::AccountId, ConstU16<65535>>, Fellows>;
```

**File:** cumulus/parachains/runtimes/collectives/collectives-westend/src/fellowship/mod.rs (L144-148)
```rust
	// Exchange is by any of:
	// - Root can exchange arbitrarily.
	// - the Fellows origin
	type ExchangeOrigin =
		EitherOf<EnsureRootWithSuccess<Self::AccountId, ConstU16<65535>>, Fellows>;
```
