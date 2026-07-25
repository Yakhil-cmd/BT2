### Title
`checkConsistency()` validates base-fee bound votes independently, allowing `LowerBoundBaseFee > UpperBoundBaseFee` after epoch ratification — (`File: kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency()` validates each governance vote against the **current** effective `ParamSet` in isolation. When two votes targeting `kip71.lowerboundbasefee` and `kip71.upperboundbasefee` are cast in the same epoch, each passes its individual check, but the combined ratified state can violate the invariant `LowerBoundBaseFee ≤ UpperBoundBaseFee`. No cross-validation is performed at ratification time. The resulting broken parameter pair permanently corrupts the dynamic base-fee calculation in `NextMagmaBlockBaseFee()`.

---

### Finding Description

`checkConsistency()` in `kaiax/gov/headergov/impl/header.go` enforces the bound relationship at **vote time** by reading the current `ParamSet`:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads current effective params
    if vote.Value().(uint64) > params.UpperBoundBaseFee {
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads current effective params
    if vote.Value().(uint64) < params.LowerBoundBaseFee {
        return ErrUpperBoundBaseFee
    }
``` [1](#0-0) 

`GetParamSet(blockNum)` returns the params effective **before** the current epoch's votes take effect. Votes cast within the same epoch are invisible to each other's consistency check. At the epoch boundary, `getExpectedGovernance()` collects all votes from the previous epoch and ratifies them together without any cross-parameter validation:

```go
for _, voteBlock := range sortedVoteBlocks {
    vote := prevEpochVotes[voteBlock]
    govs.Add(string(vote.Name()), vote.Value())   // no cross-check here
}
return headergov.NewGovData(govs)
``` [2](#0-1) 

`VerifyGov()` only checks that the header's `Governance` field matches the locally-derived expected governance — it does not validate that the combined parameter set is internally consistent:

```go
if !reflect.DeepEqual(expected, actual) {
    return ErrGovVerification
}
``` [3](#0-2) 

`ParamSet.Set()` also applies each parameter independently with no cross-field validation: [4](#0-3) 

---

### Impact Explanation

When `LowerBoundBaseFee > UpperBoundBaseFee` is ratified, `NextMagmaBlockBaseFee()` enters a degenerate loop:

```go
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
    parentBaseFee = upperBoundBaseFee          // clamp to the lower value (e.g. 100 gwei)
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
    parentBaseFee = lowerBoundBaseFee
}
// ... decrease path:
if nextBaseFee.Cmp(lowerBoundBaseFee) < 0 {
    return makeEvenByFloor(lowerBoundBaseFee)  // always returns 500 gwei
}
``` [5](#0-4) 

With `Lower = 500 gwei`, `Upper = 100 wei`:
- Any `parentBaseFee ≥ 100 gwei` is clamped to `upper = 100 gwei`
- The decrease path fires, but `nextBaseFee < lower (500 gwei)` → returns `500 gwei`
- Every subsequent block: `parentBaseFee = 500 gwei` → clamped to `100 gwei` → returns `500 gwei`

The base fee is **permanently stuck at `LowerBoundBaseFee`** regardless of network congestion. The intended `UpperBoundBaseFee` ceiling is never enforced. All users pay the stuck fee; excess fees are burnt. The dynamic fee mechanism (KIP-71) is rendered non-functional for the lifetime of this governance configuration.

---

### Likelihood Explanation

**`none` governance mode** (any council member can vote): A single council member who proposes two blocks in the same epoch can cast both conflicting votes. Two different council members can each cast one conflicting vote. Each vote passes `checkConsistency()` independently because it checks against the pre-epoch params.

**`single` governance mode** (Mainnet): Requires the governing node to intentionally or accidentally cast both conflicting votes in the same epoch. This is a privileged path.

The `none` mode path is the semi-trusted trigger: council members are trusted for consensus but not necessarily for governance correctness.

---

### Recommendation

Cross-validate the combined effect of all pending votes in the epoch at ratification time. In `getExpectedGovernance()` (or a new `verifyRatifiedParamSet()` called from `VerifyGov()`), after assembling the full `govs` map, check:

```go
newLower := govs[gov.Kip71LowerBoundBaseFee]  // if present
newUpper := govs[gov.Kip71UpperBoundBaseFee]  // if present
// resolve against current params for whichever is absent
if resolvedLower > resolvedUpper {
    // reject the epoch governance block
}
```

Alternatively, add the cross-check inside `checkConsistency()` by also inspecting already-accumulated votes for the current epoch when validating a new bound vote.

---

### Proof of Concept

Assume `epoch = 1000`, current params: `LowerBoundBaseFee = 25 gwei`, `UpperBoundBaseFee = 750 gwei`.

**Step 1** — Block 1100 (epoch 1, block 100): governing node (or any council member in `none` mode) proposes a block and casts:
```
Vote: kip71.lowerboundbasefee = 500_000_000_000  (500 gwei)
```
`checkConsistency`: `500 gwei ≤ 750 gwei (current Upper)` → **passes**.

**Step 2** — Block 1200 (epoch 1, block 200): same or different council member proposes a block and casts:
```
Vote: kip71.upperboundbasefee = 100_000_000_000  (100 gwei)
```
`checkConsistency`: `100 gwei ≥ 25 gwei (current Lower)` → **passes**.

**Step 3** — Block 2000 (epoch boundary): `getExpectedGovernance(2000)` collects both votes and ratifies:
```json
{ "kip71.lowerboundbasefee": 500000000000, "kip71.upperboundbasefee": 100000000000 }
```
`VerifyGov` only checks `expected == actual` — **passes**. No cross-validation.

**Step 4** — Block 2001 onward: `GetParamSet(2001)` returns `Lower = 500 gwei`, `Upper = 100 gwei`. Every call to `NextMagmaBlockBaseFee()` returns `500 gwei` regardless of gas usage. The KIP-71 dynamic fee mechanism is permanently broken. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L147-152)
```go
	// (5)
	if !reflect.DeepEqual(expected, actual) {
		logger.Error("Governance mismatch", "expected", expected, "actual", actual)
		return ErrGovVerification
	}

```

**File:** kaiax/gov/headergov/impl/header.go (L156-215)
```go
// checkConsistency checks if vote values are consistent with chain states such as other parameters and validator set.
func (h *headerGovModule) checkConsistency(blockNum uint64, vote headergov.VoteData) error {
	switch vote.Name() {
	case gov.GovernanceGoverningNode:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}

		// we'll use blockNum-1 for the blocknumber of GetCouncil since blockNum cannot be available(eg. vote)
		// it's definite that the valSet vote is not included in this block
		// so the council(blockNum - 1) and council(blockNum) should be same
		council, err := h.ValSet.GetCouncil(blockNum - 1)
		if err != nil {
			return err
		}

		if slices.Contains(council, params.GoverningNode) {
			return nil
		}
		return ErrGovNodeNotInValSetList
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
	case gov.AddValidator, gov.RemoveValidator:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}
		if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
			return ErrGovNodeInValSetVoteValue
		}
		return nil
		// These votes are valid as long as it passes the format checks in NewVoteData(). No more checks here.
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
	default:
		return ErrInvalidKeyValue
	}
}
```

**File:** kaiax/gov/headergov/impl/header.go (L217-233)
```go
// The blockNum's epoch index must be greater than 0. That is, it must be blockNum >= epoch.
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

**File:** kaiax/gov/paramset.go (L79-84)
```go
	case Kip71LowerBoundBaseFee:
		p.LowerBoundBaseFee, ok = cv.(uint64)
	case Kip71MaxBlockGasUsedForBaseFee:
		p.MaxBlockGasUsedForBaseFee, ok = cv.(uint64)
	case Kip71UpperBoundBaseFee:
		p.UpperBoundBaseFee, ok = cv.(uint64)
```

**File:** params/kip71_config.go (L58-129)
```go
func (kc *KIP71Config) NextMagmaBlockBaseFee(parentHeaderNumber *big.Int, parentHeaderBaseFee *big.Int, parentHeaderGasUsed uint64) *big.Int {
	// governance parameters
	lowerBoundBaseFee := new(big.Int).SetUint64(kc.LowerBoundBaseFee)
	upperBoundBaseFee := new(big.Int).SetUint64(kc.UpperBoundBaseFee)
	makeEvenByCeil(lowerBoundBaseFee)
	makeEvenByFloor(upperBoundBaseFee)

	// If the parent is the magma disabled block or genesis, then return the lowerBoundBaseFee (default 25ston)
	if parentHeaderNumber.Cmp(new(big.Int).SetUint64(0)) == 0 || parentHeaderBaseFee == nil {
		return makeEvenByFloor(lowerBoundBaseFee)
	}

	var baseFeeDenominator *big.Int
	if kc.BaseFeeDenominator == 0 {
		// To avoid panic, set the fluctuation range small
		baseFeeDenominator = new(big.Int).SetUint64(64)
	} else {
		baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
	}
	gasTarget := kc.GasTarget
	upperGasLimit := kc.MaxBlockGasUsedForBaseFee

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
	} else {
		// shortcut. If parentBaseFee is already reached lower bound, do not calculate.
		if parentBaseFee.Cmp(lowerBoundBaseFee) == 0 {
			return makeEvenByFloor(lowerBoundBaseFee)
		}
		// Otherwise if the parent block used less gas than its target,
		// the baseFee of the next block should decrease.
		// baseFeeDelta = parentBaseFee * (gasTarget - parentGasUsed) / gasTarget / baseFeeDenominator
		gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := x.Div(y, baseFeeDenominator)

		nextBaseFee := x.Sub(parentBaseFee, baseFeeDelta)
		if nextBaseFee.Cmp(lowerBoundBaseFee) < 0 {
			return makeEvenByFloor(lowerBoundBaseFee)
		}
		return makeEvenByFloor(nextBaseFee)
	}
}
```
