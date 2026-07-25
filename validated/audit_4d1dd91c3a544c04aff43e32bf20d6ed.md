The code confirms the vulnerability claim. Let me trace the exact path:

**`validateNonEpochVRank` only checks subset validity, not completeness:** [1](#0-0) 

It checks that every address in `report` is a known candidate (`isNonCandContained`), that the list is sorted, and that there are no duplicates. There is no check that every *failing* candidate is present.

**`VerifyHeader` accepts an empty or partial VRank for non-epoch blocks:** [2](#0-1) 

`len(header.VRank) == 0` returns `nil` immediately, and a non-empty but partial VRank passes `validateNonEpochVRank` as long as the subset is valid.

**`cfReport` reads directly from `header.VRank` with no completeness enforcement:** [3](#0-2) 

**CFS scores are incremented only for addresses present in `cfReport`:** [4](#0-3) 

If a candidate is omitted from `header.VRank`, `cfReport` returns them absent, and `cpMatrix.Increment` is never called for them.

**The byzantine filter does not help here.** `byzantineFilter` discards the F *highest* reporter totals per candidate to defend against score *inflation*. Score *suppression* (a reporter simply never reporting a candidate) is not addressed — there is nothing to filter out. [5](#0-4) 

---

### Title
Proposer Can Suppress Candidate CFS Scores by Omitting Failing Candidates from `header.VRank` — (`kaiax/vrank/impl/consensus.go`)

### Summary
`VerifyHeader` for non-epoch blocks only validates that addresses in `header.VRank` are a subset of known candidates. It does not verify completeness — that all failing candidates are reported. A malicious block proposer can craft a `header.VRank` that omits one or more failing candidates. Honest validators accept the block (their `VerifyHeader` passes), and the omitted candidates' CFS scores are never incremented, shielding them from ejection.

### Finding Description
`validateNonEpochVRank` enforces three properties: no non-candidate addresses, sorted order, no duplicates. It does not enforce that the report is the *full* set of failing candidates. Because `cfReport` reads directly from the committed `header.VRank`, and `applyBlocksForCPMatrix` increments `cpMatrix` only for addresses present in `cfReport`, any candidate omitted by the proposer receives zero score contribution for that block. Over an epoch, a colluding proposer can repeatedly omit a target candidate, keeping their CFS score below the ejection threshold indefinitely.

### Impact Explanation
The CFS score is the mechanism by which the permissionless validator system ejects underperforming or misbehaving candidates. Suppressing a candidate's CFS score is a direct privilege escalation in the validator-set management system: a candidate that should be ejected remains in `CandTesting`, continues to participate in consensus, and continues to receive rewards. This corrupts the protected chain state governing validator set composition.

### Likelihood Explanation
Any validator that holds a proposer slot can execute this attack unilaterally. Proposer rotation means every validator gets turns. Honest co-validators sign the block because their own `VerifyHeader` passes — they have no mechanism to detect or reject an incomplete VRank. No majority collusion is required; a single malicious proposer suffices.

### Recommendation
`validateNonEpochVRank` must enforce completeness, not just subset validity. The verifier should independently recompute the expected failing-candidate set (or a commitment to it) and reject any `header.VRank` that omits entries. One approach: require the proposer to commit to the full failing set and have validators check it against their own `EvaluateCandidates` result, or store a hash of the expected report in the block and verify it during `VerifyHeader`.

### Proof of Concept
1. Set up a consensus test with candidates A, B, C where B and C both fail to respond in time.
2. Have the proposer craft `header.VRank` containing only `[B]` (omitting C), which is a valid sorted, deduplicated subset of candidates.
3. Call `VerifyHeader` — it returns `nil` (accepted).
4. Call `GetCFS(blockNum)` — assert C's score is 0 while B's score is 1.
5. Repeat across enough blocks to show C's CFS score never reaches the ejection threshold despite consistent failures.

### Citations

**File:** kaiax/vrank/impl/consensus.go (L59-71)
```go
	if len(header.VRank) == 0 {
		return nil
	}

	report, err := vrank.DecodeReport(header.VRank)
	if err != nil {
		return vrank.ErrInvalidVRankFormat
	}
	candidates, err := v.Valset.GetCandTesting(number - 1)
	if err != nil {
		return err
	}
	return validateNonEpochVRank(report, candidates)
```

**File:** kaiax/vrank/impl/consensus.go (L148-158)
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
```

**File:** kaiax/vrank/impl/getter.go (L39-55)
```go
func (v *VRankModule) cfReport(blockNum uint64) ([]common.Address, error) {
	if !v.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) {
		return nil, vrank.ErrNotPermissionless
	}
	if blockNum%v.vrankEpoch() == 0 {
		return []common.Address{}, nil
	}

	header := v.Chain.GetHeaderByNumber(blockNum)
	if header == nil {
		return nil, vrank.ErrHeaderNotFound
	}
	if len(header.VRank) == 0 {
		return []common.Address{}, nil
	}
	return vrank.DecodeReport(header.VRank)
}
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
