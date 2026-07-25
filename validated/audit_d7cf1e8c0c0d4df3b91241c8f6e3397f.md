### Title
Malicious Proposer Can Submit Empty VRank to Suppress Candidate Failure Scores, Enabling Unresponsive Candidates to Pass Epoch-End Promotion — (`kaiax/vrank/impl/consensus.go`)

---

### Summary

`VerifyHeader` unconditionally accepts `header.VRank = nil` on any non-epoch-start block after the permissionless fork. Because `PrepareHeader` also legitimately encodes "no failures" as nil, honest nodes cannot distinguish a genuine empty report from a maliciously suppressed one. A single malicious proposer can exploit this to zero-out CFS contributions for every block they propose, reducing the accumulated failure scores of unresponsive candidates and allowing them to pass the epoch-end VRank test and be promoted to `ValActive`.

---

### Finding Description

**Entry point — `VerifyHeader` early-return:** [1](#0-0) 

For non-epoch-start blocks, `VerifyHeader` returns `nil` immediately when `len(header.VRank) == 0`. No candidate-membership check, no cross-reference against `GetCandTesting(N-1)`, nothing. This is the same code path taken by an honest proposer who observed zero failures, so honest validators accept the block and sign it.

**`PrepareHeader` confirms nil is the legitimate "no failures" encoding:** [2](#0-1) 

An honest proposer sets `header.VRank = nil` when `len(report) == 0`. The protocol therefore cannot distinguish a genuine empty report from a suppressed one.

**`cfReport()` propagates the empty result into CFS aggregation:** [3](#0-2) 

When `header.VRank` is empty, `cfReport()` returns `[]common.Address{}`. `applyBlocksForCPMatrix` then calls `cpMatrix.Increment` for zero candidates, so no failure is recorded in the CP matrix for that block. [4](#0-3) 

**Byzantine filter does not protect against suppression:** [5](#0-4) 

`byzantineFilter` discards the **top** F reporter scores to defend against inflation. A malicious proposer who contributes `0` (by suppressing) is never in the top-F set — the filter provides no protection against under-reporting.

---

### Impact Explanation

A single malicious validator acting as proposer can suppress CFS increments for every block they propose. In a round-robin committee of N validators, the attacker controls roughly 1/N of all blocks. Over an epoch, candidates who genuinely failed to respond accumulate fewer CFS points than they should. If the suppression is sufficient to keep their score below the `isPassVrankTest` threshold (in `kaiax/valset/impl/transition_context.go`), those candidates are promoted from `CandTesting` to `ValActive` instead of being demoted to `Registered`. This is a validator-set privilege escalation: unresponsive nodes gain active-validator status and the associated block-proposal rights and rewards they should not have.

---

### Likelihood Explanation

The attacker needs only to be a single validator in the active set — no majority collusion, no key compromise, no external service. The attack is silent (empty VRank is indistinguishable from a legitimate no-failure round), requires no special tooling beyond modifying the proposer's `PrepareHeader` logic, and can be sustained across every epoch indefinitely.

---

### Recommendation

`VerifyHeader` must not treat an empty VRank as unconditionally valid. For non-epoch-start blocks, when `GetCandTesting(N-1)` returns a non-empty candidate list, an empty VRank should be rejected unless the proposer provides a signed attestation that no candidates failed (or the protocol is redesigned so that "no failures" is encoded as an explicit non-nil value, e.g. `RLPEncode([])` = `0xc0`, distinct from `nil`). Concretely:

```go
// Non-epoch-start block
candidates, err := v.Valset.GetCandTesting(number - 1)
if err != nil {
    return err
}
if len(header.VRank) == 0 {
    // Only accept nil if there are genuinely no candidates to report on.
    if len(candidates) > 0 {
        return vrank.ErrMissingVRankReport
    }
    return nil
}
```

Alternatively, mandate that `PrepareHeader` always encodes an explicit empty list (`0xc0`) rather than `nil` when candidates exist, and reject `nil` in `VerifyHeader` when `GetCandTesting` is non-empty.

---

### Proof of Concept

1. Start a chain with the permissionless fork active and at least one `CandTesting` candidate `C`.
2. Arrange for `C` to be unresponsive (does not send `VRankCandidate` messages).
3. For every block the malicious proposer `P` proposes in the epoch, set `header.VRank = nil` instead of encoding `C`'s failure.
4. Honest validators call `VerifyHeader` → `len(header.VRank) == 0` → `return nil` → block accepted and finalized.
5. At epoch end, call `GetCFS(epochEnd - 1)`. Assert `cfs[C] == 0` (or below the demotion threshold) despite `C` having failed every round `P` proposed.
6. Observe that the valset transition promotes `C` to `ValActive` instead of demoting it to `Registered`. [1](#0-0) [3](#0-2) [6](#0-5)

### Citations

**File:** kaiax/vrank/impl/consensus.go (L58-61)
```go
	// Non-epoch-start block
	if len(header.VRank) == 0 {
		return nil
	}
```

**File:** kaiax/vrank/impl/consensus.go (L137-139)
```go
	if len(report) == 0 {
		return nil, nil
	}
```

**File:** kaiax/vrank/impl/getter.go (L51-54)
```go
	if len(header.VRank) == 0 {
		return []common.Address{}, nil
	}
	return vrank.DecodeReport(header.VRank)
```

**File:** kaiax/vrank/impl/scoring.go (L159-193)
```go
func (v *VRankModule) applyBlocksForCPMatrix(start, end uint64, seed vrank.CPMatrix) (vrank.CPMatrix, error) {
	cpMatrix := seed.Clone()
	for blockNum := start; blockNum <= end; blockNum++ {
		header := v.Chain.GetHeaderByNumber(blockNum)
		if header == nil {
			return nil, vrank.ErrHeaderNotFound
		}

		cfReport, err := v.cfReport(blockNum)
		if err != nil {
			return nil, err
		}

		roundByte, err := v.RoundReader.Round(header)
		if err != nil {
			return nil, err
		}
		round := uint64(roundByte)
		reporter, err := v.Valset.GetProposer(blockNum, round)
		if err != nil {
			return nil, err
		}
		// Record the proposer in the CP matrix even when this block has no cfReport,
		// so ProposerCount() reflects every proposer seen in the epoch.
		cpMatrix.AddProposer(reporter)

		for _, candidate := range cfReport {
			if _, ok := cpMatrix[candidate]; !ok {
				logger.Warn("cfReport contains address not in candidates list; skipping", "blockNum", blockNum, "candidate", candidate.Hex())
				continue
			}
			cpMatrix.Increment(candidate, reporter)
		}
	}
	return cpMatrix, nil
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
