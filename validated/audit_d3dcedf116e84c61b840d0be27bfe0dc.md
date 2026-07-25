### Title
Governance Vote Consistency Check Validates Each KIP-71 Bound Vote Against Current State Only, Allowing Two Validators to Jointly Set `LowerBoundBaseFee > UpperBoundBaseFee`, Breaking the Base-Fee Floor Invariant — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` in `headerGovModule` validates each governance vote for `Kip71LowerBoundBaseFee` and `Kip71UpperBoundBaseFee` against the **current** `ParamSet`, not against the **pending** state after all votes in the same epoch are applied. In "none" governance mode, two different block-proposing validators can independently cast votes that are individually valid but collectively produce `LowerBoundBaseFee > UpperBoundBaseFee`. When this invalid state is applied at the epoch boundary, `NextMagmaBlockBaseFee` in `params/kip71_config.go` produces a base fee that violates the fee-floor invariant, allowing transactions to be included at fees below the governance-set minimum.

---

### Finding Description

**Root cause — `kaiax/gov/headergov/impl/header.go`, `checkConsistency`:**

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) > params.UpperBoundBaseFee {   // checks against CURRENT upper
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) < params.LowerBoundBaseFee {   // checks against CURRENT lower
        return ErrUpperBoundBaseFee
    }
```

Each vote is validated in isolation against the live `ParamSet`. There is no check against other votes already cast in the same epoch.

**Epoch application — `kaiax/gov/headergov/impl/header.go`, `getExpectedGovernance`:**

```go
for _, voteBlock := range sortedVoteBlocks {
    vote := prevEpochVotes[voteBlock]
    govs.Add(string(vote.Name()), vote.Value())   // both votes applied unconditionally
}
```

`prevEpochVotes` is keyed by block number (`map[uint64]VoteData`). Votes for **different** parameters from different blocks in the same epoch are all applied. No cross-parameter consistency check is performed at application time.

**Attack scenario (none-mode chain, current `lower=25 gkei`, `upper=750 gkei`):**

| Block | Proposer | Vote | Consistency check result |
|-------|----------|------|--------------------------|
| 50 | Validator A | `LowerBoundBaseFee = 700 gkei` | 700 ≤ 750 → **accepted** |
| 60 | Validator B | `UpperBoundBaseFee = 600 gkei` | 600 ≥ 25 → **accepted** |

At epoch boundary both votes are applied: `LowerBoundBaseFee = 700 gkei`, `UpperBoundBaseFee = 600 gkei` → **lower > upper**.

**Corrupted execution — `params/kip71_config.go`, `NextMagmaBlockBaseFee`:**

```go
lowerBoundBaseFee = 700 gkei   // makeEvenByCeil(700) = 700
upperBoundBaseFee = 600 gkei   // makeEvenByFloor(600) = 600

// parentBaseFee clamping (e.g. parentBaseFee = 650):
if parentBaseFee >= 600 { parentBaseFee = 600 }   // fires: 650 ≥ 600
else if parentBaseFee <= 700 { parentBaseFee = 700 } // also fires: 600 ≤ 700
// → parentBaseFee = 700

// gasUsed > gasTarget path:
nextBaseFee = 700 + delta
if nextBaseFee > 600 { return 600 }   // always fires
// → base fee = 600 gkei  (BELOW the 700 gkei floor)
```

The base fee is permanently stuck at `upperBoundBaseFee` (600 gkei) whenever gas usage exceeds the target, which is below `lowerBoundBaseFee` (700 gkei). The `VerifyMagmaHeader` check accepts this value because all nodes compute the same (incorrect) expected fee.

---

### Impact Explanation

The fee-floor invariant `baseFee ≥ LowerBoundBaseFee` is broken. Every block produced while gas usage exceeds the target carries a base fee of 600 gkei instead of the governance-mandated minimum of 700 gkei. All transaction fees collected at this lower rate reduce KAIA revenue flowing to validators, KIF, KEF, and KPF. The effect persists until a corrective governance vote is applied in a subsequent epoch. This is an unauthorized reduction in fee charges affecting KAIA distribution, matching the allowed impact category.

---

### Likelihood Explanation

Requires "none" governance mode (the default: `DefaultGovernanceMode = "none"` in `params/governance_params.go`) and two distinct block proposers in the same epoch casting votes for the two different KIP-71 bound parameters. No collusion is required — each validator independently votes for what it considers a reasonable value. The check that prevents a single vote from violating the invariant (`newLower > currentUpper`) gives a false sense of safety while leaving the cross-vote case unguarded.

---

### Recommendation

Add a cross-parameter consistency check at epoch application time in `getExpectedGovernance` (or in `PartialParamSet.Add`): after collecting all votes for an epoch, verify that the resulting `LowerBoundBaseFee ≤ UpperBoundBaseFee`. If the combined set is invalid, reject the conflicting vote (e.g., the later one) or revert to the current value for the offending parameter.

Alternatively, extend `checkConsistency` to also inspect any pending vote for the complementary bound already recorded in the current epoch's vote map before accepting a new bound vote.

---

### Proof of Concept

1. Deploy a chain with `GovernanceMode = "none"`, `LowerBoundBaseFee = 25 gkei`, `UpperBoundBaseFee = 750 gkei`, epoch = 100.
2. At block 10 (epoch 0), Validator A proposes a block containing `Vote{Kip71LowerBoundBaseFee, 700 gkei}`. `checkConsistency` passes: 700 ≤ 750.
3. At block 20 (epoch 0), Validator B proposes a block containing `Vote{Kip71UpperBoundBaseFee, 600 gkei}`. `checkConsistency` passes: 600 ≥ 25.
4. At block 100 (epoch boundary), `getExpectedGovernance` applies both votes. The resulting `ParamSet` has `LowerBoundBaseFee = 700`, `UpperBoundBaseFee = 600`.
5. Starting at block 101, `NextMagmaBlockBaseFee` is called with the new config. With any `parentGasUsed > GasTarget`, it returns 600 gkei — 100 gkei below the governance-set floor of 700 gkei.
6. `VerifyMagmaHeader` accepts the block because all nodes compute the same expected value of 600 gkei.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L179-192)
```go
	case gov.Kip71LowerBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) > params.UpperBoundBaseFee {
			return ErrLowerBoundBaseFee
		} else {
			return nil
		}
	case gov.Kip71UpperBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) < params.LowerBoundBaseFee {
			return ErrUpperBoundBaseFee
		} else {
			return nil
		}
```

**File:** kaiax/gov/headergov/impl/header.go (L218-233)
```go
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
	prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
	prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
	govs := make(gov.PartialParamSet)

	sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
	slices.Sort(sortedVoteBlocks)

	for _, voteBlock := range sortedVoteBlocks {
		vote := prevEpochVotes[voteBlock]
		govs.Add(string(vote.Name()), vote.Value())
	}

	// assert(len(headergov.NewGovData(govs).Items()) == len(govs))
	return headergov.NewGovData(govs)
}
```

**File:** params/kip71_config.go (L80-109)
```go
	// check the case of upper/lowerBoundBaseFee is updated by governance mechanism
	parentBaseFee := parentHeaderBaseFee
	if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
		parentBaseFee = upperBoundBaseFee
	} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
		parentBaseFee = lowerBoundBaseFee
	}

	// upper gas limit cut off the impulse of used gas to upper bound
	parentGasUsed := min(parentHeaderGasUsed, upperGasLimit)
	if parentGasUsed == gasTarget {
		return makeEvenByFloor(parentBaseFee)
	} else if parentGasUsed > gasTarget {
		// shortcut. If parentBaseFee is already reached upperbound, do not calculate.
		if parentBaseFee.Cmp(upperBoundBaseFee) == 0 {
			return makeEvenByFloor(upperBoundBaseFee)
		}
		// If the parent block used more gas than its target,
		// the baseFee of the next block should increase.
		// baseFeeDelta = max(1, parentBaseFee * (parentGasUsed - gasTarget) / gasTarget / baseFeeDenominator)
		gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := math.BigMax(x.Div(y, baseFeeDenominator), common.Big1)

		nextBaseFee := x.Add(parentBaseFee, baseFeeDelta)
		if nextBaseFee.Cmp(upperBoundBaseFee) > 0 {
			return makeEvenByFloor(upperBoundBaseFee)
		}
		return makeEvenByFloor(nextBaseFee)
```

**File:** params/governance_params.go (L40-41)
```go
	DefaultGovernanceMode            = "none"
	DefaultGoverningNode             = "0x0000000000000000000000000000000000000000"
```
