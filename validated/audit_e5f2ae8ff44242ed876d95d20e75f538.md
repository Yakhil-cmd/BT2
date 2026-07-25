I have all the code needed to make a definitive determination. Let me trace the exact attack path.

## Exact Code Trace

**`checkConsistency` for `Kip71LowerBoundBaseFee` and `Kip71UpperBoundBaseFee`:**

Both cases call `h.GetParamSet(blockNum)` and check the new vote value against the *currently effective* counterpart bound. [1](#0-0) 

**`GetParamSet(blockNum)` resolves to `PrevEpochStart`:**

```
PrevEpochStart(blockNum, epoch, isKore=true) = blockNum - blockNum%epoch - epoch
``` [2](#0-1) [3](#0-2) 

**`History.Search` finds the max governance block ≤ the given number:** [4](#0-3) 

**Governance updates are stored at epoch blocks and rebuild `h.history`:** [5](#0-4) 

## Concrete Attack Trace (epoch=100, Kore enabled)

Initial state: `h.governances = {0: {Lower=25, Upper=750}}`, `h.history = {0: {Lower=25, Upper=750}}`.

**Step 1 — Vote `LowerBound=500` at block 150 (epoch 1):**
- `GetParamSet(150)` → `PrevEpochStart(150,100,true) = 0` → `Search(0)` → `{Lower=25, Upper=750}`
- Check: `500 > 750`? No → **vote accepted**

**Step 2 — Block 200 (epoch block) processed:**
- `HandleGov(200, {Lower=500})` → `h.governances[200] = {Lower=500}` → history rebuilt:
  - `h.history = {0: {Lower=25, Upper=750}, 200: {Lower=500, Upper=750}}`

**Step 3 — Vote `UpperBound=200` at block 250 (epoch 2):**
- `GetParamSet(250)` → `PrevEpochStart(250,100,true) = 100` → `Search(100)` → max block ≤ 100 is **block 0** (block 200 > 100, excluded) → returns `{Lower=25, Upper=750}`
- Check: `200 < 25`? No → **vote accepted**

**Step 4 — Block 300 (epoch block) processed:**
- `HandleGov(300, {Upper=200})` → history rebuilt:
  - `h.history = {0: {Lower=25, Upper=750}, 200: {Lower=500, Upper=750}, 300: {Lower=500, Upper=200}}`

**Step 5 — Blocks in epoch 4 (400–499):**
- `GetParamSet(450)` → `PrevEpochStart(450,100,true) = 300` → `Search(300)` → `{Lower=500, Upper=200}` — **inverted**

## Root Cause

`GetParamSet(blockNum)` returns params from **two epochs ago** (`prevEpochStart = currentEpochStart - epoch`). When a vote is cast in epoch N+1, the check uses params from epoch N-1, not epoch N. The governance update from epoch N (stored at the epoch-N+1 epoch block) is at a block number *greater than* `prevEpochStart`, so `Search` skips it. This creates a one-epoch blind spot: the two bounds are never checked against each other across the epoch boundary. [6](#0-5) [7](#0-6) 

## Impact on `NextMagmaBlockBaseFee`

With `Lower=500 > Upper=200`, the function's sequential clamp logic produces oscillating, erratic base fees (e.g., parentBaseFee=300 → clamped to Upper=200 → decrease path → nextBaseFee < Lower=500 → returns Lower=500; next block → clamped to Upper=200 again). The KIP-71 invariant is permanently violated. All nodes compute the same broken value deterministically (no chain split), but the base fee mechanism is durably corrupted — a valid "invalid state transition / durable loss of core chain functionality" impact. [8](#0-7) 

## Governance Mode Constraint

The attack requires two distinct council members to each be a block proposer in their respective epochs. In `"single"` governance mode (Kaia mainnet default), only the governing node can vote after the Permissionless fork, so the attack collapses to a single trusted actor. In `"none"` mode, any two council members can execute it without majority collusion. [9](#0-8) 

---

### Title
Cross-Epoch Base-Fee Bound Inversion via Stale `GetParamSet` in `checkConsistency` — (`kaiax/gov/headergov/impl/header.go`)

### Summary
`checkConsistency` validates each KIP-71 bound vote independently against `GetParamSet(blockNum)`, which returns params from **two epochs prior** to the vote block. A vote in epoch N+1 cannot see the governance update committed at the epoch-N+1 epoch block (stored at a block number above `prevEpochStart`). Two council-member proposers in consecutive epochs can therefore craft votes that individually pass validation but jointly invert `LowerBoundBaseFee > UpperBoundBaseFee` in the effective `ParamSet`.

### Finding Description
`GetParamSet(blockNum)` computes `prevEpochStart = blockNum - blockNum%epoch - epoch` and calls `History.Search(prevEpochStart)`, which returns the latest governance snapshot at or before that block. A governance update from epoch-N votes is written to `h.governances` at the epoch-N+1 epoch block (block number = `(N+1)*epoch`). For a vote cast at block `(N+1)*epoch + k`, `prevEpochStart = N*epoch`, and `Search(N*epoch)` finds only governance at `N*epoch` or earlier — the epoch-N update at `(N+1)*epoch` is invisible. The two bound checks therefore operate on different effective states: the `LowerBound` check in epoch N sees epoch-N-1 params; the `UpperBound` check in epoch N+1 also sees epoch-N-1 params (not epoch-N params). No cross-epoch joint validation exists. [1](#0-0) [2](#0-1) 

### Impact Explanation
After the two epoch blocks are committed, `h.history` permanently contains a `ParamSet` with `LowerBoundBaseFee=500 > UpperBoundBaseFee=200`. Every subsequent call to `NextMagmaBlockBaseFee` with these params produces oscillating, undefined base fees. The KIP-71 invariant is durably violated; the base fee mechanism is permanently broken for all blocks in the affected epoch and beyond. This constitutes an invalid state transition and durable loss of core chain functionality. [10](#0-9) [11](#0-10) 

### Likelihood Explanation
Requires `"none"` governance mode and two council members who are block proposers in consecutive epochs. On a chain with a large council and long epochs, any council member will eventually be a proposer. The attack does not require a majority and is achievable by two colluding (or independently acting) council members. On Kaia mainnet (`"single"` mode), the attack reduces to a single malicious governing node.

### Recommendation
In `checkConsistency`, when validating `Kip71LowerBoundBaseFee` or `Kip71UpperBoundBaseFee`, also check the vote against any pending (not-yet-effective) bound changes accumulated in the current epoch's votes (`h.groupedVotes`). Alternatively, validate the joint invariant `Lower <= Upper` at the epoch block when `getExpectedGovernance` assembles the final `GovData`, rejecting the governance update if the combined result would violate the invariant. [12](#0-11) [13](#0-12) 

### Proof of Concept
```
epoch = 100, Kore enabled
Initial: Lower=25, Upper=750

Block 150: vote Lower=500
  GetParamSet(150) → PrevEpochStart=0 → Search(0) → {Lower=25, Upper=750}
  Check: 500 > 750? No → ACCEPTED

Block 200 (epoch block): HandleGov({Lower=500})
  h.history[200] = {Lower=500, Upper=750}

Block 250: vote Upper=200
  GetParamSet(250) → PrevEpochStart=100 → Search(100) → max≤100 = block 0 → {Lower=25, Upper=750}
  Check: 200 < 25? No → ACCEPTED

Block 300 (epoch block): HandleGov({Upper=200})
  h.history[300] = {Lower=500, Upper=200}  ← INVERTED

Block 450: GetParamSet(450) → PrevEpochStart=300 → Search(300) → {Lower=500, Upper=200}
  NextMagmaBlockBaseFee oscillates between 200 and 500 indefinitely
```

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L101-109)
```go
	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}

	return h.checkConsistency(blockNum, vote)
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

**File:** kaiax/gov/headergov/impl/getter.go (L11-23)
```go
func (h *headerGovModule) GetParamSet(blockNum uint64) gov.ParamSet {
	h.mu.RLock()
	defer h.mu.RUnlock()

	prevEpochStart := PrevEpochStart(blockNum, h.epoch, h.isKoreHF(blockNum))
	gh := h.history
	gp, err := gh.Search(prevEpochStart)
	if err != nil {
		logger.Warn("No param set", "blockNum", blockNum, "prevEpochStart", prevEpochStart)
		return *gov.GetDefaultGovernanceParamSet()
	}
	return gp
}
```

**File:** kaiax/gov/headergov/impl/getter.go (L72-80)
```go
func PrevEpochStart(blockNum, epoch uint64, isKore bool) uint64 {
	if blockNum <= epoch {
		return 0
	}
	if !isKore {
		blockNum -= 1
	}
	return blockNum - blockNum%epoch - epoch
}
```

**File:** kaiax/gov/headergov/history.go (L12-33)
```go
func GovsToHistory(govs map[uint64]GovData) History {
	gh := make(map[uint64]gov.ParamSet)

	// we must ensure that gov history is not empty
	gh[0] = *gov.GetDefaultGovernanceParamSet()

	sortedNums := make([]uint64, 0, len(govs))
	for num := range govs {
		sortedNums = append(sortedNums, num)
	}
	slices.Sort(sortedNums)

	gp := *gov.GetDefaultGovernanceParamSet()
	for _, num := range sortedNums {
		govData := govs[num]
		if err := gp.SetFromMap(govData.Items()); err != nil {
			continue
		}
		gh[num] = gp
	}

	return gh
```

**File:** kaiax/gov/headergov/history.go (L37-50)
```go
func (g *History) Search(blockNum uint64) (gov.ParamSet, error) {
	idx := uint64(0)
	for num := range *g {
		if idx < num && num <= blockNum {
			idx = num
		}
	}
	if ret, ok := (*g)[idx]; ok {
		return ret, nil
	}

	// This can happen in tests. On production, it must never happen.
	return gov.ParamSet{}, ErrNoHistory
}
```

**File:** kaiax/gov/headergov/impl/execution.go (L65-71)
```go
func (h *headerGovModule) AddGov(blockNum uint64, gov headergov.GovData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.governances[blockNum] = gov
	h.history = headergov.GovsToHistory(h.governances)
}
```

**File:** params/kip71_config.go (L58-128)
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
```
