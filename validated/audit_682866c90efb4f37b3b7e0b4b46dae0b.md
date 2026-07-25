### Title
Governance vote can set `kip71.gastarget` to zero, causing division-by-zero panic in `NextMagmaBlockBaseFee` and halting consensus — (File: `params/kip71_config.go`, `kaiax/gov/param.go`)

---

### Summary

The `kip71.gastarget` governance parameter has no zero-value guard in its `FormatChecker`. A governing node (or any council member in `none` mode) can cast a valid governance vote setting `kip71.gastarget = 0`. Once the vote takes effect at the next epoch boundary, every subsequent call to `NextMagmaBlockBaseFee()` with a non-zero `parentGasUsed` performs an integer division by zero (`big.Int.Div(x, 0)`), causing a Go runtime panic. This panic fires in both block production (`worker.commitNewWork`) and block verification (`VerifyMagmaHeader`), halting the chain on all honest nodes.

---

### Finding Description

**Root cause — missing zero-check in `FormatChecker`:**

`Kip71GasTarget` is registered with `noopFormatChecker`, which unconditionally returns `true`: [1](#0-0) 

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // accepts any uint64, including 0
    ...
    DefaultValue: uint64(30000000),
},
```

Compare this to `Kip71BaseFeeDenominator`, which correctly rejects zero: [2](#0-1) 

```go
Kip71BaseFeeDenominator: {
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // explicit zero guard
    },
```

`BaseFeeDenominator` also has a runtime fallback in `NextMagmaBlockBaseFee`: [3](#0-2) 

No equivalent guard exists for `GasTarget`.

**Division-by-zero in `NextMagmaBlockBaseFee`:**

When `parentGasUsed > gasTarget` (the normal case for any block with transactions), the function reaches: [4](#0-3) 

```go
gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // Div(x, 0) → panic
```

And in the `parentGasUsed < gasTarget` branch: [5](#0-4) 

```go
gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // Div(x, 0) → panic
```

The only safe path is `parentGasUsed == gasTarget == 0`, which never occurs in practice since any block with transactions has `parentGasUsed > 0`.

**Call sites that panic:**

Block production — called every block in `worker.commitNewWork`: [6](#0-5) 

Block verification — called for every Magma-era block header: [7](#0-6) 

---

### Impact Explanation

Once the governance vote for `kip71.gastarget = 0` takes effect at the next epoch boundary, every node that attempts to produce or verify a block with non-zero gas usage panics. This causes:

- **Block production halt**: the proposer's worker goroutine panics and cannot produce new blocks.
- **Block verification halt**: all nodes panic when verifying any incoming block, causing consensus divergence — honest nodes cannot accept new blocks.
- **Chain halt**: the network stops finalizing blocks until the parameter is corrected via another governance vote, which itself requires block production to work.

This matches the allowed impact: *"Invalid state transition … or consensus divergence on honest nodes."*

---

### Likelihood Explanation

In `single` governance mode (Mainnet), the governing node must cast the vote. In `none` mode, any council member can. The trigger is a semi-trusted actor with legitimate voting rights who either makes an error or acts maliciously. The missing guard means there is no on-chain rejection of the value `0` — the vote passes `FormatChecker` and is ratified normally. The `SetDefaultsForGenesis` zero-check only runs at genesis and does not protect against post-genesis governance updates: [8](#0-7) 

---

### Recommendation

Add a non-zero guard to `Kip71GasTarget`'s `FormatChecker`, mirroring the existing guard on `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0
    },
    ...
},
```

Additionally, add a runtime guard in `NextMagmaBlockBaseFee` analogous to the existing `BaseFeeDenominator` fallback:

```go
if kc.GasTarget == 0 {
    return makeEvenByFloor(lowerBoundBaseFee) // safe fallback
}
```

---

### Proof of Concept

1. On a Magma-enabled network in `none` or `single` governance mode, the governing node calls `governance_vote("kip71.gastarget", 0)`.
2. The vote passes `PartialParamSet.Add` because `noopFormatChecker` returns `true` for `uint64(0)`.
3. At the next epoch block, the vote is ratified and `kip71.gastarget = 0` becomes the effective parameter.
4. On the first block after the epoch where any transaction is included (`parentGasUsed > 0`):
   - `NextMagmaBlockBaseFee` is called with `gasTarget = 0`.
   - `parentGasUsed > gasTarget` is true.
   - `x.Div(x, new(big.Int).SetUint64(0))` panics with `"division by zero"`.
5. All nodes panic during `VerifyMagmaHeader`; the proposer panics during `commitNewWork`. The chain halts. [9](#0-8) [10](#0-9)

### Citations

**File:** kaiax/gov/param.go (L160-162)
```go
func noopFormatChecker(cv any) bool {
	return true
}
```

**File:** kaiax/gov/param.go (L310-315)
```go
	Kip71BaseFeeDenominator: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(uint64)
			return ok && v != 0
		},
```

**File:** kaiax/gov/param.go (L324-333)
```go
	Kip71GasTarget: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.GasTarget, nil
		},
		DefaultValue: uint64(30000000),
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

**File:** params/kip71_config.go (L70-76)
```go
	var baseFeeDenominator *big.Int
	if kc.BaseFeeDenominator == 0 {
		// To avoid panic, set the fluctuation range small
		baseFeeDenominator = new(big.Int).SetUint64(64)
	} else {
		baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
	}
```

**File:** params/kip71_config.go (L88-103)
```go
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
```

**File:** params/kip71_config.go (L118-121)
```go
		gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := x.Div(y, baseFeeDenominator)
```

**File:** work/worker.go (L381-383)
```go
		pset := self.govModule.GetParamSet(nextBlockNum.Uint64())
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
```

**File:** params/config.go (L717-722)
```go
	// StakingUpdateInterval must be nonzero because it is used as denominator
	if c.Governance.Reward.StakingUpdateInterval == 0 {
		c.Governance.Reward.StakingUpdateInterval = DefaultStakeUpdateInterval
		logger.Warn("Override the default staking update interval to the chain config", "interval",
			c.Governance.Reward.StakingUpdateInterval)
	}
```
