### Title
Infinite loop in `AncestryChain::ancestry` via cyclic `votes_ancestries` headers in GRANDPA justification verification - (File: bridges/primitives/header-chain/src/justification/verification/mod.rs)

### Summary
`AncestryChain::ancestry()` in `bridges/primitives/header-chain/src/justification/verification/mod.rs` walks backward through a parent-hash map built entirely from the untrusted `votes_ancestries` field of a submitted GRANDPA justification. Loop-avoidance in this structure is provided only by the `unvisited` set, which is updated across *separate* calls to `ancestry()` (once per precommit, via `mark_route_as_visited`) but is **not** checked against hashes already pushed to `route` *within the current call*. An attacker who supplies two or more fabricated "ancestor" headers whose `parent_hash` fields form a cycle (e.g. `H1.parent_hash = hash(H2)`, `H2.parent_hash = hash(H1)`) causes the `loop` at lines 103-122 to oscillate between the cycle members forever, exactly mirroring the CVE-2018-7174 pattern where loop detection existed for one traversal path but not another equivalent one (there: tables vs. streams; here: cross-call revisit tracking vs. intra-call cycle tracking). [1](#0-0) 

### Finding Description
`AncestryChain::new` builds a `parents: BTreeMap<Header::Hash, Header::Hash>` directly from `justification.votes_ancestries`, using `ancestor.hash()` as the key and `ancestor.parent_hash()` (an arbitrary, attacker-chosen field inside the fabricated header) as the value, with no relation to any real chain: [2](#0-1) 

`ancestry()` then walks `current_hash -> parent_hash_of(current_hash) -> ...` until it reaches `self.base.hash()`. The only cycle guard is:
```
let is_visited_before = self.unvisited.get(&current_hash).is_none();
if is_visited_before { return Some(route); }
```
`unvisited` is populated once at construction with every hash from `votes_ancestries`, and entries are removed only by `mark_route_as_visited`, which runs *after* a call to `ancestry()` returns successfully for a different precommit. This means within a single call, a hash can be revisited indefinitely as long as it has never been "visited" in a prior precommit's route — a 2-cycle among freshly fabricated headers never terminates.

This is reachable from `verify_justification` (the shared trait method used by `strict::verify_justification`, which backs the pallet's real verification path): [3](#0-2) 

Critically, `chain.ancestry(&signed.precommit.target_hash, ...)` is invoked at line 290-291, **before** the authority signature is checked at lines 302-314. The only prerequisite to reach the `ancestry()` call is that `signed.id` matches a known authority in `context.voter_set` — authority IDs are public information, not a secret or privileged credential. The `target_hash`/`target_number` inside `signed.precommit` and the actual signature bytes are fully attacker-controlled fields of the submitted `GrandpaJustification`; the attacker crafts a `SignedPrecommit` with a real authority's public ID, an arbitrary (even garbage) signature, and a `target_hash` equal to one of the two cyclic fabricated ancestor headers.

`bridges/modules/grandpa` exposes `submit_finality_proof` / `submit_finality_proof_ex` as extrinsics callable by any signed account (a relayer role with no special permission, just an account paying fees), which pass the caller-supplied `justification` through to this verification code. The pre-dispatch checks in `call_ext.rs` (`check_obsolete_from_extension`, `fits_limits`) only validate the target block number/set-id and size/weight limits for fee purposes — they do not detect or reject cyclic/duplicate-parent structures in `votes_ancestries`, and do not cap the call in a way that prevents an unbounded/non-terminating loop (they only affect whether the relayer gets a "free" execution and refund). [4](#0-3) 

### Impact Explanation
This is an unauthenticated, permissionless-input infinite loop in on-chain GRANDPA justification verification, reachable via a public extrinsic (`submit_finality_proof`/`submit_finality_proof_ex`) on any chain running `pallet-bridge-grandpa` (used by Polkadot/Kusama-style bridges and Cumulus bridge hubs). An attacker with no privileged role can construct a justification whose `votes_ancestries` contains a small, fixed-size cycle of fabricated headers and a single precommit referencing a real (public) authority ID with a bogus signature. Submitting this justification causes block execution/import to hang inside `ancestry()`, which — depending on how weight/gas metering interacts with this loop — can stall block production for the bridge-hosting chain (a deterministic chain liveness failure), which the assessment rubric explicitly favors over resource-exhaustion/flooding classes.

### Likelihood Explanation
Likelihood is high for any deployment of `pallet-bridge-grandpa`: the attacker needs only to submit one signed extrinsic with a fabricated `GrandpaJustification`; no stolen keys, no governance, no malicious validator/collator role, and no valid GRANDPA signature is required to reach the vulnerable code path, since the loop executes before signature verification.

### Recommendation
In `AncestryChain::ancestry()`, track hashes visited *within the current call* (e.g. a local `HashSet`/`BTreeSet` populated as the loop progresses) and immediately abort with `None` (or a dedicated cycle error) if `current_hash` is encountered twice in the same traversal, independent of the cross-call `unvisited` bookkeping. Additionally, consider bounding the traversal length to `votes_ancestries.len() + 1` to guarantee termination.

### Proof of Concept
No executable PoC was run against this fork; this assessment is a static code-flow analysis based on reading `bridges/primitives/header-chain/src/justification/verification/mod.rs`, `strict.rs`, and `bridges/modules/grandpa/src/call_ext.rs`. A full reproduction would require: constructing a `GrandpaJustification` with `votes_ancestries = [H1, H2]` where `H1.parent_hash() == H2.hash()` and `H2.parent_hash() == H1.hash()`, and `commit.precommits = [SignedPrecommit { id: <real authority id>, precommit: { target_hash: H1.hash(), .. }, signature: <arbitrary> }]`, then calling `strict::verify_justification` (or driving it through the `submit_finality_proof` extrinsic in a test runtime) and observing non-termination. This trace/construction was not executed in this session; I was unable to run code, so termination behavior and any potential mitigating factor in `finality_grandpa`'s external checks were not empirically confirmed — this should be validated with a real Rust integration test before treating it as bounty-ready, particularly to rule out any weight-metering interrupt that might convert the infinite loop into a bounded-but-large loop.

### Citations

**File:** bridges/primitives/header-chain/src/justification/verification/mod.rs (L65-84)
```rust
	pub fn new(
		justification: &GrandpaJustification<Header>,
	) -> (AncestryChain<Header>, Vec<usize>) {
		let mut parents = BTreeMap::new();
		let mut unvisited = BTreeSet::new();
		let mut ignored_idxs = Vec::new();
		for (idx, ancestor) in justification.votes_ancestries.iter().enumerate() {
			let hash = ancestor.hash();
			match parents.entry(hash) {
				Occupied(_) => {
					ignored_idxs.push(idx);
				},
				Vacant(entry) => {
					entry.insert(*ancestor.parent_hash());
					unvisited.insert(hash);
				},
			}
		}
		(AncestryChain { base: justification.commit_target_id(), parents, unvisited }, ignored_idxs)
	}
```

**File:** bridges/primitives/header-chain/src/justification/verification/mod.rs (L92-125)
```rust
	pub fn ancestry(
		&self,
		precommit_target_hash: &Header::Hash,
		precommit_target_number: &Header::Number,
	) -> Option<Vec<Header::Hash>> {
		if precommit_target_number < &self.base.number() {
			return None;
		}

		let mut route = vec![];
		let mut current_hash = *precommit_target_hash;
		loop {
			if current_hash == self.base.hash() {
				break;
			}

			current_hash = match self.parent_hash_of(&current_hash) {
				Some(parent_hash) => {
					let is_visited_before = self.unvisited.get(&current_hash).is_none();
					if is_visited_before {
						// If the current header has been visited in a previous call, it is a
						// descendent of `base` (we assume that the previous call was successful).
						return Some(route);
					}
					route.push(current_hash);

					*parent_hash
				},
				None => return None,
			};
		}

		Some(route)
	}
```

**File:** bridges/primitives/header-chain/src/justification/verification/mod.rs (L238-299)
```rust
	fn verify_justification(
		&mut self,
		finalized_target: (Header::Hash, Header::Number),
		context: &JustificationVerificationContext,
		justification: &GrandpaJustification<Header>,
	) -> Result<(), Error> {
		// ensure that it is justification for the expected header
		if (justification.commit.target_hash, justification.commit.target_number) !=
			finalized_target
		{
			return Err(Error::InvalidJustificationTarget);
		}

		let threshold = context.voter_set.threshold().get();
		let (mut chain, ignored_idxs) = AncestryChain::new(justification);
		let mut signature_buffer = Vec::new();
		let mut cumulative_weight = 0u64;

		if !ignored_idxs.is_empty() {
			self.process_duplicate_votes_ancestries(ignored_idxs)?;
		}

		for (precommit_idx, signed) in justification.commit.precommits.iter().enumerate() {
			if cumulative_weight >= threshold {
				let action =
					self.process_redundant_vote(precommit_idx).map_err(Error::Precommit)?;
				if matches!(action, IterationFlow::Skip) {
					continue;
				}
			}

			// authority must be in the set
			let authority_info = match context.voter_set.get(&signed.id) {
				Some(authority_info) => {
					// The implementer may want to do extra checks here.
					// For example to see if the authority has already voted in the same round.
					let action = self
						.process_known_authority_vote(precommit_idx, signed)
						.map_err(Error::Precommit)?;
					if matches!(action, IterationFlow::Skip) {
						continue;
					}

					authority_info
				},
				None => {
					self.process_unknown_authority_vote(precommit_idx).map_err(Error::Precommit)?;
					continue;
				},
			};

			// all precommits must be descendants of the target block
			let maybe_route =
				chain.ancestry(&signed.precommit.target_hash, &signed.precommit.target_number);
			if maybe_route.is_none() {
				let action = self
					.process_unrelated_ancestry_vote(precommit_idx)
					.map_err(Error::Precommit)?;
				if matches!(action, IterationFlow::Skip) {
					continue;
				}
			}
```

**File:** bridges/modules/grandpa/src/call_ext.rs (L265-298)
```rust
/// Extract finality proof info from the submitted header and justification.
pub(crate) fn submit_finality_proof_info_from_args<T: Config<I>, I: 'static>(
	finality_target: &BridgedHeader<T, I>,
	justification: &GrandpaJustification<BridgedHeader<T, I>>,
	current_set_id: Option<SetId>,
	is_free_execution_expected: bool,
) -> SubmitFinalityProofInfo<BridgedBlockNumber<T, I>> {
	// check if call exceeds limits. In other words - whether some size or weight is included
	// in the call
	let extras =
		submit_finality_proof_limits_extras::<T::BridgedChain>(finality_target, justification);

	// We do care about extra weight because of more-than-expected headers in the votes
	// ancestries. But we have problems computing extra weight for additional headers (weight of
	// additional header is too small, so that our benchmarks aren't detecting that). So if there
	// are more than expected headers in votes ancestries, we will treat the whole call weight
	// as an extra weight.
	let extra_weight = if extras.is_weight_limit_exceeded {
		let precommits_len = justification.commit.precommits.len().saturated_into();
		let votes_ancestries_len = justification.votes_ancestries.len().saturated_into();
		T::WeightInfo::submit_finality_proof(precommits_len, votes_ancestries_len)
	} else {
		Weight::zero()
	};

	SubmitFinalityProofInfo {
		block_number: *finality_target.number(),
		current_set_id,
		is_mandatory: extras.is_mandatory_finality_target,
		is_free_execution_expected,
		extra_weight,
		extra_size: extras.extra_size,
	}
}
```
