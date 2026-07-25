### Title
Cross-Epoch Governance Vote Consistency Check Allows Inverted KIP-71 Base Fee Bounds — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` validates each governance vote in isolation against the **currently effective** parameter set. It does not account for the combined effect of two votes cast in the same epoch. In `none` governance mode, two independent GC members can each cast a valid vote — one lowering `UpperBoundBaseFee` below the current `LowerBoundBaseFee`, and one raising `LowerBoundBaseFee` above the current `UpperBoundBaseFee` — and both votes pass on-chain verification. After epoch ratification, the invariant `LowerBoundBaseFee ≤ UpperBoundBaseFee` is permanently broken, causing `NextMagmaBlockBaseFee` to compute inverted base fees for every subsequent block.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` performs two independent, single-parameter checks:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads CURRENT effective params
    if vote.Value().(uint64) > params.UpperBoundBaseFee {
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads CURRENT effective params
    if vote.Value().(uint64) < params.LowerBoundBaseFee {
        return ErrUpperBoundBaseFee
    }
```

Each check compares the proposed value only against the **currently ratified** counterpart, not against any other pending vote in the same epoch. `getExpectedGovernance` — which assembles the ratification payload at the epoch boundary — performs no cross-parameter consistency check either:

```go
for _, voteBlock := range sortedVoteBlocks {
    vote := prevEpochVotes[voteBlock]
    govs.Add(string(vote.Name()), vote.Value())   // no invariant check
}
```

**Attack scenario (none-mode, epoch = E):**

| Block | Voter | Vote | `checkConsistency` result |
|-------|-------|------|--------------------------|
| E+100 | GC member A | `kip71.upperboundbasefee = 100` | passes: 100 ≥ 25 (current lower) |
| E+200 | GC member B | `kip71.lowerboundbasefee = 200` | passes: 200 ≤ 750 (current upper) |
| 2E    | proposer | ratifies both | **Lower=200, Upper=100** |

After ratification, `NextMagmaBlockBaseFee` in `params/kip71_config.go` receives inverted bounds:

```go
// Lower=200, Upper=100 after governance
parentBaseFee := parentHeaderBaseFee
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {   // >= 100 → true for almost any fee
    parentBaseFee = upperBoundBaseFee              // clamp to 100 (the "upper", now lower)
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 { // <= 200 → true for small fees
    parentBaseFee = lowerBoundBaseFee              // clamp to 200 (the "lower", now higher)
}
```

With inverted bounds:
- **High gas usage** (> `gasTarget`): fee is clamped to `upperBoundBaseFee = 100` and stays there — the fee **decreases** when it should increase.
- **Low gas usage** (< `gasTarget`): fee is clamped to `lowerBoundBaseFee = 200` and stays there — the fee **increases** when it should decrease.

The EIP-1559-style feedback loop is permanently reversed. `VerifyMagmaHeader` does not validate `Lower ≤ Upper`; it only checks that the block's `baseFee` equals `NextMagmaBlockBaseFee(...)`. All nodes compute the same wrong value, so blocks are accepted with the incorrect fee.

---

### Impact Explanation

Every transaction's `effectiveGasPrice` is computed from the broken base fee. Users are charged incorrect fees on every block after the epoch boundary:

- When network is congested, the base fee is stuck at the (now-lower) `UpperBoundBaseFee`, undercharging senders and under-rewarding validators/funds.
- When network is idle, the base fee is stuck at the (now-higher) `LowerBoundBaseFee`, overcharging senders.

This is a persistent, chain-wide incorrect fee charge affecting KAIA. The state cannot self-correct without a new governance vote that restores the correct ordering, and there is no on-chain guard that detects or rejects the inverted state.

---

### Likelihood Explanation

In `none` governance mode, any GC member may cast a vote for any parameter. Two members acting independently (or one member voting for both parameters in the same epoch without realising the combined effect) can trigger this. No coordination or majority collusion is required — each individual vote is valid and passes `VerifyVote`. The vulnerability is latent in every `none`-mode deployment and in any `single`-mode chain where the governing node votes for both KIP-71 bound parameters in the same epoch.

---

### Recommendation

Add a cross-parameter consistency check at the epoch ratification boundary inside `getExpectedGovernance` (or in a new `verifyRatifiedParamSet` step called from `VerifyGov`). After assembling the full ratified `PartialParamSet`, verify:

```go
if lower, ok1 := govs[gov.Kip71LowerBoundBaseFee]; ok1 {
    if upper, ok2 := govs[gov.Kip71UpperBoundBaseFee]; ok2 {
        if lower.(uint64) > upper.(uint64) {
            return ErrInvalidBaseFeeRange
        }
    }
}
```

Additionally, `checkConsistency` should look up any **pending vote in the current epoch** for the counterpart parameter and validate against that pending value, not only the currently effective value.

---

### Proof of Concept

**Setup:** `none`-mode chain, epoch = 1000, current params: `Lower=25_000_000_000`, `Upper=750_000_000_000`.

1. **Block 1100** — GC member A proposes a block with `header.Vote = ("kip71.upperboundbasefee", 50_000_000_000)`.
   - `checkConsistency`: `50_000_000_000 >= 25_000_000_000` → **passes**.

2. **Block 1500** — GC member B proposes a block with `header.Vote = ("kip71.lowerboundbasefee", 100_000_000_000)`.
   - `checkConsistency`: `100_000_000_000 <= 750_000_000_000` → **passes**.

3. **Block 2000** (epoch boundary) — `getExpectedGovernance` collects both votes, no cross-check, writes `header.Governance = {"kip71.upperboundbasefee": 50_000_000_000, "kip71.lowerboundbasefee": 100_000_000_000}`. `VerifyGov` accepts it.

4. **Block 2001 onward** — `GetParamSet(2001)` returns `Lower=100_000_000_000`, `Upper=50_000_000_000`. `NextMagmaBlockBaseFee` clamps every `parentBaseFee ≥ 50 Gwei` to `50 Gwei` (upper), and every `parentBaseFee < 50 Gwei` to `100 Gwei` (lower). The base fee oscillates incorrectly and all transactions are charged the wrong fee permanently. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** params/kip71_config.go (L45-56)
```go
func (kc *KIP71Config) VerifyMagmaHeader(headerBaseFee *big.Int, parentHeaderNumber *big.Int, parentHeaderBaseFee *big.Int, parentHeaderGasUsed uint64) error {
	if headerBaseFee == nil {
		return fmt.Errorf("header is missing baseFee")
	}
	// Verify the baseFee is correct based on the parent header.
	expectedBaseFee := kc.NextMagmaBlockBaseFee(parentHeaderNumber, parentHeaderBaseFee, parentHeaderGasUsed)
	if headerBaseFee.Cmp(expectedBaseFee) != 0 {
		return fmt.Errorf("invalid baseFee: have %s, want %s, parentBaseFee %s, parentGasUsed %d",
			headerBaseFee, expectedBaseFee, parentHeaderBaseFee, parentHeaderGasUsed)
	}
	return nil
}
```

**File:** params/kip71_config.go (L80-128)
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
