### Title
Incorrect Strict Inequality in `checkConsistency` Allows `LowerBoundBaseFee == UpperBoundBaseFee` Governance Vote — (File: `kaiax/gov/headergov/impl/header.go`)

### Summary

`checkConsistency` in the header governance module uses strict `>` / `<` comparisons when validating `kip71.lowerboundbasefee` and `kip71.upperboundbasefee` votes. This allows a vote that sets `LowerBoundBaseFee == UpperBoundBaseFee` to pass validation and be ratified, which — when the shared value is odd — causes `NextMagmaBlockBaseFee` to operate with an inverted bound pair (`lower > upper` after even-rounding), producing base-fee values that violate the intended fee bounds and corrupt per-block fee collection and reward distribution.

### Finding Description

In `checkConsistency`:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) > params.UpperBoundBaseFee {   // BUG: should be >=
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) < params.LowerBoundBaseFee {   // BUG: should be <=
        return ErrUpperBoundBaseFee
    }
``` [1](#0-0) 

The declared error strings confirm the intended invariant is `lower < upper` (not merely `lower != upper`):

```go
ErrLowerBoundBaseFee = errors.New("lowerboundbasefee is greater than upperboundbasefee")
ErrUpperBoundBaseFee = errors.New("upperboundbasefee is less than lowerboundbasefee")
``` [2](#0-1) 

Because the checks are strict, a vote setting `LowerBoundBaseFee = UpperBoundBaseFee = X` passes. When `X` is odd, `NextMagmaBlockBaseFee` applies:

```go
makeEvenByCeil(lowerBoundBaseFee)   // X → X+1
makeEvenByFloor(upperBoundBaseFee)  // X → X-1
``` [3](#0-2) 

This produces `lowerBound = X+1 > upperBound = X-1`. The subsequent clamping logic:

```go
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
    parentBaseFee = upperBoundBaseFee   // X-1
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
    parentBaseFee = lowerBoundBaseFee   // X+1
}
``` [4](#0-3) 

clamps `parentBaseFee` to `X-1` (the "upper" bound) for any value in `[X-1, X+1]`. When `parentGasUsed < gasTarget`, the shortcut for `parentBaseFee == lowerBoundBaseFee` does not fire (since `X-1 ≠ X+1`), so the code computes `nextBaseFee = X-1 - delta`. Because `X-1 - delta < X+1 = lowerBoundBaseFee`, it returns `lowerBoundBaseFee = X+1`, which **exceeds the upper bound** `X-1`. The base fee oscillates between `X-1` and `X+1` across blocks, violating the invariant that `baseFee ≤ UpperBoundBaseFee`. [5](#0-4) 

The ratified parameter is applied to every block's `VerifyMagmaHeader` call via `BlockValidator.validateHeader`: [6](#0-5) 

### Impact Explanation

The base fee is the primary fee-collection mechanism post-Magma. An inverted bound pair causes `NextMagmaBlockBaseFee` to return values outside the governance-intended range on every block. Because the base fee is burned or distributed as part of block reward accounting, incorrect base-fee values corrupt per-block KAIA fee collection and reward distribution for the duration the misconfigured parameters remain effective (until the next governance epoch overrides them).

### Likelihood Explanation

The trigger is a governance vote cast by the governing node (single mode) or any GC member (none mode) — a semi-trusted actor. The misconfiguration requires setting both bounds to the same odd value, which is an unusual but syntactically valid vote that the current check does not reject. The error message text itself documents the intent to block this case, confirming the check is simply missing the equality arm.

### Recommendation

Change the two comparisons in `checkConsistency` to inclusive inequalities:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) >= params.UpperBoundBaseFee {  // was >
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) <= params.LowerBoundBaseFee {  // was <
        return ErrUpperBoundBaseFee
    }
``` [1](#0-0) 

### Proof of Concept

1. Current `LowerBoundBaseFee = 25_000_000_000`, `UpperBoundBaseFee = 750_000_000_000`.
2. Governing node casts vote: `kip71.lowerboundbasefee = 750_000_000_001` (odd).
3. `checkConsistency`: `750_000_000_001 > 750_000_000_000` → **false** (equal check missing) → vote accepted.
4. Simultaneously or subsequently, governing node votes `kip71.upperboundbasefee = 750_000_000_001`.
5. `checkConsistency`: `750_000_000_001 < 750_000_000_001` → **false** → vote accepted.
6. Both votes ratified at epoch boundary; effective from next epoch.
7. `NextMagmaBlockBaseFee`: `lowerBound = 750_000_000_002`, `upperBound = 750_000_000_000`.
8. For any `parentGasUsed < gasTarget`: base fee returned = `750_000_000_002`, which exceeds `upperBoundBaseFee = 750_000_000_000` — invariant broken, incorrect fee charged every block until governance corrects the parameters. [1](#0-0) [7](#0-6)

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

**File:** kaiax/gov/headergov/impl/error.go (L19-20)
```go
	ErrLowerBoundBaseFee        = errors.New("lowerboundbasefee is greater than upperboundbasefee")
	ErrUpperBoundBaseFee        = errors.New("upperboundbasefee is less than lowerboundbasefee")
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

**File:** blockchain/block_validator.go (L195-205)
```go
	if v.config.IsMagmaForkEnabled(header.Number) {
		// Skip governance-dependent validation when gov module is not registered.
		if v.mGov != nil {
			govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
			if err := govParamSet.ToKip71Config().VerifyMagmaHeader(header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
				return err
			}
		}
	} else if header.BaseFee != nil {
		return ErrInvalidBaseFee
	}
```
