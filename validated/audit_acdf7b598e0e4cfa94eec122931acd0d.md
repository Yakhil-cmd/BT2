Looking at the code carefully to trace the full attack path.

### Title
Proposer CFS Suppression via Incomplete VRank — Unauthorized CandTesting → ValActive Promotion - (`kaiax/vrank/impl/consensus.go`)

### Summary

`validateNonEpochVRank` enforces only subset membership, sort order, and deduplication on `header.VRank`. It never checks that the report is **complete** (i.e., that every genuinely failing candidate is included). A single malicious `ValActive` proposer can submit an empty or partial VRank for every block they propose, suppressing CFS accumulation for a colluding `CandTesting` candidate. At epoch end, the candidate's artificially-low CFS passes `isPassVrankTest` and the candidate is promoted to `ValActive`, receiving staking rewards without meeting the reliability requirement.

---

### Finding Description

**Step 1 — Empty VRank passes `VerifyHeader` unconditionally.**

For non-epoch-start blocks, `VerifyHeader` short-circuits on an empty field: [1](#0-0) 

A proposer can always set `header.VRank = nil` and the check returns `nil`.

**Step 2 — `validateNonEpochVRank` has no completeness check.**

When VRank is non-empty, the only structural checks are subset membership, sort order, and deduplication: [2](#0-1) 

There is no assertion that the report equals the full set of candidates who failed to respond. A strict subset (including the empty set) is accepted.

**Step 3 — Empty VRank produces an empty cfReport, contributing zero to CFS.**

`cfReport` reads directly from `header.VRank`: [3](#0-2) 

An empty field returns an empty slice; `applyBlocksForCPMatrix` then calls `cpMatrix.Increment` zero times for that block, so the colluding candidate's per-reporter score stays at zero for every block the malicious proposer proposes. [4](#0-3) 

**Step 4 — The byzantine filter does not protect against suppression.**

The filter is designed to discard the **top-F** reporter scores to neutralise false accusations (inflation). It removes the highest scores, not the lowest: [5](#0-4) 

A suppressing proposer contributes a score of **0** for the candidate. The filter removes the top-F honest reporters' scores, leaving the suppressor's zero untouched. Suppression is therefore not corrected by the filter — it is amplified: the malicious proposer both withholds their own report and causes one additional honest score to be discarded (because their presence increases `ProposerCount()`, raising F by `floor(1/3)` = 0 for small sets, but the zero score itself is never filtered out).

**Step 5 — Suppressed CFS causes `isPassVrankTest` to return `true`.**

At epoch-end `applyEpochTransition` calls `isPassVrankTest` for every `CandTesting` node: [6](#0-5) [7](#0-6) 

If the candidate's CFS is below `CfsThreshold` (default 300) due to suppression, the test passes and the candidate enters `ValActive` via `competeOrDemote`.

---

### Impact Explanation

A colluding `(proposer P1, candidate C1)` pair can execute the following:

1. During consensus of block N−1, C1 deliberately does not respond to `VRankPreprepare` (or P1 simply does not forward it to C1).
2. P1, as proposer of block N, writes `header(N).VRank = nil` (empty). This passes `VerifyHeader`.
3. Honest proposers who observe C1 failing do record it in their VRank, but P1's blocks contribute zero to C1's CFS.
4. Over an epoch of 86 400 blocks, P1 suppresses C1's failures for every block P1 proposes (~epoch/N blocks). If the suppressed CFS stays below 300, C1 passes `isPassVrankTest`.
5. C1 is promoted `CandTesting → ValActive` and begins receiving staking rewards.

**Corrupted state:** `cpMatrix[C1][P1]` remains 0 instead of the true positive count; derived CFS is artificially low; validator state machine transitions C1 to `ValActive` without authority.

**Asset impact:** C1 receives staking reward distributions it is not entitled to. This is an unauthorized reward distribution affecting KAIA staking rewards.

---

### Likelihood Explanation

- Requires only **one** colluding `ValActive` validator — no majority collusion.
- The attack is entirely passive from the chain's perspective: empty VRank is a valid, accepted value.
- No cryptographic break, no key compromise, no external service needed.
- The attack is undetectable on-chain because there is no ground-truth completeness record to compare against.
- The colluding pair needs to coordinate off-chain, but this is trivially achievable (e.g., the same operator controls both nodes).

---

### Recommendation

Add a completeness check in `validateNonEpochVRank`. After decoding the report, recompute the expected failing set from the proposer's own `EvaluateCandidates` result and require the submitted report to equal it, **or** enforce that the report must be exactly the set of candidates who did not respond (verified by 2F+1 committee attestation committed into the block). A simpler mitigation is to require that `header.VRank` is non-empty whenever `GetCandTesting(N-1)` is non-empty and at least one candidate failed — i.e., treat a missing report as "all candidates failed" rather than "no candidates failed." The current fail-open default (`len(header.VRank) == 0 → return nil`) is the root of the exploitable gap.

---

### Proof of Concept

```
Setup:
  - Epoch = 86400, CfsThreshold = 300
  - 4 ValActive validators: P1 (malicious), P2, P3, P4
  - 1 CandTesting candidate: C1 (colluding with P1)

During the epoch:
  - For every block P1 proposes (~21600 blocks):
      P1 does not send VRankPreprepare to C1.
      C1 does not respond.
      P1 writes header.VRank = nil  →  VerifyHeader returns nil.
  - For blocks proposed by P2/P3/P4:
      C1 responds normally  →  honest proposers write empty VRank for C1.

At epoch end:
  - cpMatrix[C1][P1] = 0  (suppressed)
  - cpMatrix[C1][P2] = cpMatrix[C1][P3] = cpMatrix[C1][P4] = 0  (C1 responded)
  - CFS[C1] = 0  <  300 = CfsThreshold
  - isPassVrankTest(C1) = true
  - C1 transitions CandTesting → ValActive and receives staking rewards.

Assert: VerifyHeader on P1's blocks returns nil (confirmed by code).
Assert: C1's CFS = 0 < CfsThreshold → promoted (confirmed by isPassVrankTest logic).
```

### Citations

**File:** kaiax/vrank/impl/consensus.go (L58-61)
```go
	// Non-epoch-start block
	if len(header.VRank) == 0 {
		return nil
	}
```

**File:** kaiax/vrank/impl/consensus.go (L148-159)
```go
func validateNonEpochVRank(report, candidates []common.Address) error {
	if isNonCandContained(report, candidates) {
		return vrank.ErrInvalidVRankCandidate
	}
	if !isSorted(report) {
		return vrank.ErrVRankNotSorted
	}
	if hasDuplicate(report) {
		return vrank.ErrDuplicateVRankCandidate
	}
	return nil
}
```

**File:** kaiax/vrank/impl/getter.go (L51-54)
```go
	if len(header.VRank) == 0 {
		return []common.Address{}, nil
	}
	return vrank.DecodeReport(header.VRank)
```

**File:** kaiax/vrank/impl/scoring.go (L185-191)
```go
		for _, candidate := range cfReport {
			if _, ok := cpMatrix[candidate]; !ok {
				logger.Warn("cfReport contains address not in candidates list; skipping", "blockNum", blockNum, "candidate", candidate.Hex())
				continue
			}
			cpMatrix.Increment(candidate, reporter)
		}
```

**File:** kaiax/vrank/impl/scoring.go (L209-226)
```go
func byzantineFilter(cpMatrix vrank.CPMatrix, F int) map[common.Address]uint64 {
	cfs := make(map[common.Address]uint64)
	for cand, reporterToScore := range cpMatrix {
		scores := slices.Collect(maps.Values(reporterToScore))
		slices.Sort(scores)
		if F >= len(scores) {
			// since `scores` contain non-zero scores only, F >= len(scores) can happen, in which case all scores are discarded.
			scores = nil
		} else {
			scores = scores[:len(scores)-F]
		}
		var sum uint64
		for _, t := range scores {
			sum += t
		}
		cfs[cand] = sum
	}
	return cfs
```
