## Analysis

The Aloe report's core defect is: an entity that will be penalized (the borrower) is allowed to also be the party that *triggers and collects the reward* for that penalty (the liquidator bounty), because the protocol never checks `caller != subject-of-penalty`.

The same missing-check pattern exists in Substrate's slashing/offence-reporting subsystem. The signed `report_equivocation` extrinsics in `pallet-grandpa`, `pallet-babe`, and `pallet-beefy` bind the `reporter` to `ensure_signed(origin)` and pass it straight into `R::report_offence(...)`, without ever checking that the reporter is not the offender identified inside the proof. The reporter subsequently receives a cut (`SlashRewardFraction`) of the offender's own slash, carved out of the offender's own slashed funds, and the extrinsic fee is waived (`Pays::No`) for a "valid" report.

Client-side (off-chain) code such as `substrate/client/consensus/grandpa/src/environment.rs` and `substrate/client/consensus/beefy/src/fisherman.rs` deliberately skip generating reports for equivocations committed by the node's own local keys — but that is only a courtesy heuristic in the honest reference client. It provides **no on-chain enforcement**: any signed account (including the offending validator's stash/controller, or any other account the validator controls) can submit `report_equivocation` themselves with a self-generated equivocation proof and key-ownership proof.

Relevant code:
- Signed extrinsic entry point binding `reporter = ensure_signed(origin)` with no offender-check: [1](#0-0) , and the BABE/BEEFY equivalents [2](#0-1) .
- `process_evidence` forwards `reporter` unchecked into `R::report_offence`: [3](#0-2)  and the BABE analog [4](#0-3) .
- `pallet-offences::report_offence` never filters reporter vs. offender identity, it only tracks reporters for reward distribution: [5](#0-4) .
- Reward payout mechanics that deduct the reporter's cut from the offender's own slashed imbalance: [6](#0-5)  and the staking-async equivalent [7](#0-6) .
- Off-chain-only self-report avoidance (not an on-chain guard): [8](#0-7) , [9](#0-8) .

This is a real, low-severity design gap but it is not the same failure class or blast radius as the Aloe bug (there, the "liquidator" fully captures a large incentive while the position is unfairly seized; here, the offender is slashed regardless of who reports, and merely reclaims a small governance-configured `SlashRewardFraction` slice — plus fee waiver — out of their own already-incurred slash). It weakens third-party reporting incentives and lets a caught validator recapture part of the penalty, but it does not enable unauthorized dispatch, fund theft from other users, unbacked issuance, or irreversible freezing, and it requires the attacker to already be a validator who has committed slashable misbehavior (a cost they bear regardless).

### Title
Equivocation offender can self-report to reclaim reporter reward and fee waiver - (File: substrate/frame/grandpa/src/equivocation.rs)

### Summary
`pallet-grandpa`, `pallet-babe`, and `pallet-beefy` expose a signed `report_equivocation` extrinsic where `reporter = ensure_signed(origin)` is passed unchecked to `ReportOffence::report_offence`. Neither `process_evidence` nor `pallet-offences::report_offence` verifies that the reporter differs from the offender identified by the key-ownership proof, so a validator who commits an equivocation can submit their own proof and be recorded as the "reporter," collecting the `SlashRewardFraction` cut that is supposed to incentivize independent third-party watchers, while also having the report's transaction fee waived (`Pays::No`).

### Finding Description
`report_equivocation(origin, equivocation_proof, key_owner_proof)` calls `ensure_signed(origin)` to obtain `reporter`, then forwards it (`Some(reporter)`) into `T::EquivocationReportSystem::process_evidence`. This validates the proof and offender identity via `P::check_proof`, builds an `EquivocationOffence`, and calls `R::report_offence(reporter.into_iter().collect(), offence)`. At no point is `reporter` compared against `offender`. `pallet-offences::report_offence` stores `reporters` alongside the offence and forwards them to `OnOffenceHandler::on_offence`, which (in staking / staking-async) eventually calls `pay_reporters`, paying each listed reporter `reward_proportion * slash_due`, sourced from the offender's own `slashed_imbalance`. Because a validator inherently knows about their own double-vote/equivocation (they signed both votes), they can construct a valid `EquivocationProof` and `KeyOwnershipProof` for themselves and submit the signed `report_equivocation` extrinsic from any account they control, naming that account as reporter. The only place self-reporting is discouraged is client-side courtesy code (`environment.rs`, `fisherman.rs`), which is bypassed entirely by directly submitting the signed extrinsic.

### Impact Explanation
The validator being slashed effectively reclaims a slice of their own slash (the `SlashRewardFraction`, e.g. 10%) instead of it going to whoever else might have reported the equivocation, and avoids paying the transaction fee since valid equivocation reports waive fees. This blunts the "watchdog" incentive design (rewarding honest third parties for catching misbehavior) but does not create new unbacked funds, does not affect other users' balances, and does not bypass the underlying slash itself — the offender is still slashed the full validator/nominator amounts. This is a Low/Medium severity incentive-design gap, not a fund-theft or chain-integrity bug.

### Likelihood Explanation
High likelihood of technical feasibility (no signature/origin restriction blocks it) but low economic incentive in practice: since equivocation evidence, once produced, is typically detectable and reportable by anyone (gossiped votes/blocks), a rational offender gains only a marginal, bounded benefit (partial reward recapture + fee waiver) rather than escaping the slash. It requires the attacker to already hold validator keys and to have committed a slashable equivocation, which is itself economically costly.

### Recommendation
In `EquivocationReportSystem::process_evidence` (grandpa/babe/beefy) and any similar offence-report system, after resolving `offender` via the key-ownership proof, compare it against `reporter` (when `Some`) and reject the report (or simply omit the reporter/waived-fee benefits) if `reporter == offender`'s associated account, mirroring the client-side self-equivocation check that already exists informally in `environment.rs`/`fisherman.rs` but is currently unenforced on-chain.

### Proof of Concept
Not independently executed against a live network; based on static code-path tracing only (`ensure_signed` → `process_evidence` → `ReportOffence::report_offence` → `pay_reporters`, none of which compare reporter to offender identity). A full PoC would require: (1) constructing a valid double-vote signature pair for a test validator key, (2) generating the corresponding `KeyOwnershipProof` via `Historical::prove`, (3) submitting `Grandpa::report_equivocation(RuntimeOrigin::signed(<same-or-controlled-account>), proof, key_owner_proof)`, and (4) asserting the reporter account's balance increases by `SlashRewardFraction * slash_due` while `Pays::No` is returned — analogous to the existing test `valid_equivocation_reports_dont_pay_fees` but with the reporter set to the offender's own account instead of a distinct third party.

### Citations

**File:** substrate/frame/grandpa/src/lib.rs (L200-213)
```rust
		pub fn report_equivocation(
			origin: OriginFor<T>,
			equivocation_proof: Box<EquivocationProof<T::Hash, BlockNumberFor<T>>>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			let reporter = ensure_signed(origin)?;

			T::EquivocationReportSystem::process_evidence(
				Some(reporter),
				(*equivocation_proof, key_owner_proof),
			)?;
			// Waive the fee since the report is valid and beneficial
			Ok(Pays::No.into())
		}
```

**File:** substrate/frame/beefy/src/lib.rs (L217-241)
```rust
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::report_double_voting(
			key_owner_proof.validator_count(),
			T::MaxNominators::get(),
		))]
		pub fn report_double_voting(
			origin: OriginFor<T>,
			equivocation_proof: Box<
				DoubleVotingProof<
					BlockNumberFor<T>,
					T::BeefyId,
					<T::BeefyId as RuntimeAppPublic>::Signature,
				>,
			>,
			key_owner_proof: T::KeyOwnerProof,
		) -> DispatchResultWithPostInfo {
			let reporter = ensure_signed(origin)?;

			T::EquivocationReportSystem::process_evidence(
				Some(reporter),
				EquivocationEvidenceFor::DoubleVotingProof(*equivocation_proof, key_owner_proof),
			)?;
			// Waive the fee since the report is valid and beneficial
			Ok(Pays::No.into())
		}
```

**File:** substrate/frame/grandpa/src/equivocation.rs (L175-235)
```rust
	fn process_evidence(
		reporter: Option<T::AccountId>,
		evidence: (EquivocationProof<T::Hash, BlockNumberFor<T>>, T::KeyOwnerProof),
	) -> Result<(), DispatchError> {
		let (equivocation_proof, key_owner_proof) = evidence;
		let reporter = reporter.or_else(|| pallet_authorship::Pallet::<T>::author());
		let offender = equivocation_proof.offender().clone();

		// We check the equivocation within the context of its set id (and
		// associated session) and round. We also need to know the validator
		// set count when the offence since it is required to calculate the
		// slash amount.
		let set_id = equivocation_proof.set_id();
		let round = equivocation_proof.round();
		let session_index = key_owner_proof.session();
		let validator_set_count = key_owner_proof.validator_count();

		// Validate equivocation proof (check votes are different and signatures are valid).
		if !sp_consensus_grandpa::check_equivocation_proof(equivocation_proof) {
			return Err(Error::<T>::InvalidEquivocationProof.into());
		}

		// Validate the key ownership proof extracting the id of the offender.
		let offender = P::check_proof((KEY_TYPE, offender), key_owner_proof)
			.ok_or(Error::<T>::InvalidKeyOwnershipProof)?;

		// Fetch the current and previous sets last session index.
		// For genesis set there's no previous set.
		let previous_set_id_session_index = if set_id != 0 {
			let idx = crate::SetIdSession::<T>::get(set_id - 1)
				.ok_or(Error::<T>::InvalidEquivocationProof)?;
			Some(idx)
		} else {
			None
		};

		let set_id_session_index =
			crate::SetIdSession::<T>::get(set_id).ok_or(Error::<T>::InvalidEquivocationProof)?;

		// Check that the session id for the membership proof is within the
		// bounds of the set id reported in the equivocation.
		if session_index > set_id_session_index ||
			previous_set_id_session_index
				.map(|previous_index| session_index <= previous_index)
				.unwrap_or(false)
		{
			return Err(Error::<T>::InvalidEquivocationProof.into());
		}

		let offence = EquivocationOffence {
			time_slot: TimeSlot { set_id, round },
			session_index,
			offender,
			validator_set_count,
		};

		R::report_offence(reporter.into_iter().collect(), offence)
			.map_err(|_| Error::<T>::DuplicateOffenceReport)?;

		Ok(())
	}
```

**File:** substrate/frame/babe/src/equivocation.rs (L162-198)
```rust
	fn process_evidence(
		reporter: Option<T::AccountId>,
		evidence: (EquivocationProof<HeaderFor<T>>, T::KeyOwnerProof),
	) -> Result<(), DispatchError> {
		let (equivocation_proof, key_owner_proof) = evidence;
		let reporter = reporter.or_else(|| <pallet_authorship::Pallet<T>>::author());
		let offender = equivocation_proof.offender.clone();
		let slot = equivocation_proof.slot;

		// Validate the equivocation proof (check votes are different and signatures are valid)
		if !sp_consensus_babe::check_equivocation_proof(equivocation_proof) {
			return Err(Error::<T>::InvalidEquivocationProof.into());
		}

		let validator_set_count = key_owner_proof.validator_count();
		let session_index = key_owner_proof.session();

		let epoch_index =
			*slot.saturating_sub(crate::GenesisSlot::<T>::get()) / T::EpochDuration::get();

		// Check that the slot number is consistent with the session index
		// in the key ownership proof (i.e. slot is for that epoch)
		if Pallet::<T>::session_index_for_epoch(epoch_index) != session_index {
			return Err(Error::<T>::InvalidKeyOwnershipProof.into());
		}

		// Check the membership proof and extract the offender's id
		let offender = P::check_proof((KEY_TYPE, offender), key_owner_proof)
			.ok_or(Error::<T>::InvalidKeyOwnershipProof)?;

		let offence = EquivocationOffence { slot, validator_set_count, offender, session_index };

		R::report_offence(reporter.into_iter().collect(), offence)
			.map_err(|_| Error::<T>::DuplicateOffenceReport)?;

		Ok(())
	}
```

**File:** substrate/frame/offences/src/lib.rs (L107-142)
```rust
impl<T, O> ReportOffence<T::AccountId, T::IdentificationTuple, O> for Pallet<T>
where
	T: Config,
	O: Offence<T::IdentificationTuple>,
{
	fn report_offence(reporters: Vec<T::AccountId>, offence: O) -> Result<(), OffenceError> {
		let offenders = offence.offenders();
		let slot = offence.slot();

		// Go through all offenders in the offence report and find all offenders that were spotted
		// in unique reports.
		let TriageOutcome { concurrent_offenders } =
			match Self::triage_offence_report::<O>(reporters, &slot, offenders) {
				Some(triage) => triage,
				// The report contained only duplicates, so there is no need to slash again.
				None => return Err(OffenceError::DuplicateReport),
			};

		let offenders_count = concurrent_offenders.len() as u32;

		// The amount new offenders are slashed
		let new_fraction = offence.slash_fraction(offenders_count);

		let slash_perbill: Vec<_> = (0..concurrent_offenders.len()).map(|_| new_fraction).collect();

		T::OnOffenceHandler::on_offence(
			&concurrent_offenders,
			&slash_perbill,
			offence.session_index(),
		);

		// Deposit the event.
		Self::deposit_event(Event::Offence { kind: O::ID, slot: slot.encode() });

		Ok(())
	}
```

**File:** substrate/frame/staking/src/slashing.rs (L592-651)
```rust
/// Apply a previously-unapplied slash.
pub(crate) fn apply_slash<T: Config>(
	unapplied_slash: UnappliedSlash<T::AccountId, BalanceOf<T>>,
	slash_era: EraIndex,
) {
	let mut slashed_imbalance = NegativeImbalanceOf::<T>::zero();
	let mut reward_payout = unapplied_slash.payout;

	do_slash::<T>(
		&unapplied_slash.validator,
		unapplied_slash.own,
		&mut reward_payout,
		&mut slashed_imbalance,
		slash_era,
	);

	for &(ref nominator, nominator_slash) in &unapplied_slash.others {
		do_slash::<T>(
			nominator,
			nominator_slash,
			&mut reward_payout,
			&mut slashed_imbalance,
			slash_era,
		);
	}

	pay_reporters::<T>(reward_payout, slashed_imbalance, &unapplied_slash.reporters);
}

/// Apply a reward payout to some reporters, paying the rewards out of the slashed imbalance.
fn pay_reporters<T: Config>(
	reward_payout: BalanceOf<T>,
	slashed_imbalance: NegativeImbalanceOf<T>,
	reporters: &[T::AccountId],
) {
	if reward_payout.is_zero() || reporters.is_empty() {
		// nobody to pay out to or nothing to pay;
		// just treat the whole value as slashed.
		T::Slash::on_unbalanced(slashed_imbalance);
		return;
	}

	// take rewards out of the slashed imbalance.
	let reward_payout = reward_payout.min(slashed_imbalance.peek());
	let (mut reward_payout, mut value_slashed) = slashed_imbalance.split(reward_payout);

	let per_reporter = reward_payout.peek() / (reporters.len() as u32).into();
	for reporter in reporters {
		let (reporter_reward, rest) = reward_payout.split(per_reporter);
		reward_payout = rest;

		// this cancels out the reporter reward imbalance internally, leading
		// to no change in total issuance.
		asset::deposit_slashed::<T>(reporter, reporter_reward);
	}

	// the rest goes to the on-slash imbalance handler (e.g. treasury)
	value_slashed.subsume(reward_payout); // remainder of reward division remains.
	T::Slash::on_unbalanced(value_slashed);
}
```

**File:** substrate/frame/staking-async/src/slashing.rs (L622-688)
```rust
/// Apply a previously-unapplied slash.
pub(crate) fn apply_slash<T: Config>(unapplied_slash: UnappliedSlash<T>, offence_era: EraIndex) {
	let mut slashed_imbalance = NegativeImbalanceOf::<T>::zero();
	let mut reward_payout = unapplied_slash.payout;

	if unapplied_slash.own > Zero::zero() {
		do_slash::<T>(
			&unapplied_slash.validator,
			unapplied_slash.own,
			&mut reward_payout,
			&mut slashed_imbalance,
			offence_era,
		);
	}

	for &(ref nominator, nominator_slash) in &unapplied_slash.others {
		if nominator_slash.is_zero() {
			continue;
		}

		do_slash::<T>(
			nominator,
			nominator_slash,
			&mut reward_payout,
			&mut slashed_imbalance,
			offence_era,
		);
	}

	pay_reporters::<T>(
		reward_payout,
		slashed_imbalance,
		&unapplied_slash.reporter.map(|v| crate::vec![v]).unwrap_or_default(),
	);
}

/// Apply a reward payout to some reporters, paying the rewards out of the slashed imbalance.
fn pay_reporters<T: Config>(
	reward_payout: BalanceOf<T>,
	slashed_imbalance: NegativeImbalanceOf<T>,
	reporters: &[T::AccountId],
) {
	if reward_payout.is_zero() || reporters.is_empty() {
		// nobody to pay out to or nothing to pay;
		// just treat the whole value as slashed.
		T::Slash::on_unbalanced(slashed_imbalance);
		return;
	}

	// take rewards out of the slashed imbalance.
	let reward_payout = reward_payout.min(slashed_imbalance.peek());
	let (mut reward_payout, mut value_slashed) = slashed_imbalance.split(reward_payout);

	let per_reporter = reward_payout.peek() / (reporters.len() as u32).into();
	for reporter in reporters {
		let (reporter_reward, rest) = reward_payout.split(per_reporter);
		reward_payout = rest;

		// this cancels out the reporter reward imbalance internally, leading
		// to no change in total issuance.
		asset::deposit_slashed::<T>(reporter, reporter_reward);
	}

	// the rest goes to the on-slash imbalance handler (e.g. treasury)
	value_slashed.subsume(reward_payout); // remainder of reward division remains.
	T::Slash::on_unbalanced(value_slashed);
}
```

**File:** substrate/client/consensus/grandpa/src/environment.rs (L497-507)
```rust
	pub(crate) fn report_equivocation(
		&self,
		equivocation: Equivocation<Block::Hash, NumberFor<Block>>,
	) -> Result<(), Error> {
		if let Some(local_id) = self.voter_set_state.voting_on(equivocation.round_number()) {
			if *equivocation.offender() == local_id {
				return Err(Error::Safety(
					"Refraining from sending equivocation report for our own equivocation.".into(),
				));
			}
		}
```

**File:** substrate/client/consensus/beefy/src/fisherman.rs (L139-144)
```rust
		if let Some(local_id) = self.key_store.authority_id(validators) {
			if offender_id == &local_id {
				warn!(target: LOG_TARGET, "🥩 Skipping report for own equivocation");
				return Ok(());
			}
		}
```
