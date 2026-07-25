### Title
Missing `kip71.gastarget = 0` Guard in `NextMagmaBlockBaseFee` Causes Chain-Halting Panic on All Nodes — (`params/kip71_config.go`)

### Summary

The governance parameter `kip71.gastarget` accepts zero as a valid value because its `FormatChecker` is `noopFormatChecker` in `kaiax/gov/param.go`. When `GasTarget == 0` is in effect and any block has `parentGasUsed > 0`, `NextMagmaBlockBaseFee` performs an integer division by zero (`x.Div(x, new(big.Int).SetUint64(gasTarget))`), causing a Go runtime panic. This panic is triggered inside `validateHeader` during block import and inside the block worker during block building, halting every honest node on the network.

### Finding Description

**Root cause — missing `FormatChecker` for `kip71.gastarget`:**

In `kaiax/gov/param.go`, `Kip71GasTarget` is registered with `noopFormatChecker`, which unconditionally returns `true` for any canonical value:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // ← accepts 0
    ...
    DefaultValue: uint64(30000000),
},
``` [1](#0-0) 

By contrast, `Kip71BaseFeeDenominator` — which is also used as a divisor — has an explicit non-zero check:

```go
Kip71BaseFeeDenominator: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // ← zero rejected
    },
    ...
},
``` [2](#0-1) 

**Division-by-zero in `NextMagmaBlockBaseFee`:**

`NextMagmaBlockBaseFee` uses `gasTarget` as a divisor in two places. There is a defensive guard for `BaseFeeDenominator == 0` (lines 71–76) with an explicit comment "To avoid panic", but no equivalent guard for `GasTarget == 0`:

```go
gasTarget := kc.GasTarget          // could be 0
...
if parentGasUsed == gasTarget {    // 0 == 0 → only safe if parentGasUsed is also 0
    return makeEvenByFloor(parentBaseFee)
} else if parentGasUsed > gasTarget {   // any non-zero parentGasUsed enters here
    ...
    y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // ← PANIC: divide by zero
``` [3](#0-2) 

**Panic propagates through block validation:**

`validateHeader` in `blockchain/block_validator.go` calls `VerifyMagmaHeader` → `NextMagmaBlockBaseFee` for every post-Magma block:

```go
govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
if err := govParamSet.ToKip71Config().VerifyMagmaHeader(
    header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
    return err
}
``` [4](#0-3) 

The same function is also called from `blockchain/tx_pool.go` and `work/worker.go` when building the next block. [5](#0-4) 

### Impact Explanation

Once the governance vote for `kip71.gastarget = 0` takes effect (at the next `(k+1)*epoch` block), every subsequent block whose parent had `GasUsed > 0` causes a Go runtime panic in `NextMagmaBlockBaseFee`. Because this function is called unconditionally inside `validateHeader` for all post-Magma blocks, **every honest node panics and crashes** when it attempts to import or build the next block. The chain halts completely. The corrupted governance parameter persists in the ratified header governance store and cannot be overridden without a coordinated out-of-band fix.

### Likelihood Explanation

The governing node (`governance.governingnode`) is a semi-trusted actor. In `single` governance mode (Mainnet and Kairos), only this one node can vote. An accidental vote of `governance_vote("kip71.gastarget", 0)` — analogous to the external report's Scenario 1 — is sufficient. The `PartialParamSet.Add` path used by the vote API calls `FormatChecker` before accepting the value, but `noopFormatChecker` passes zero through without error, so the vote is accepted, ratified, and applied. [6](#0-5) 

### Recommendation

1. **Short term:** Add a non-zero check to `Kip71GasTarget`'s `FormatChecker`, mirroring the existing check for `Kip71BaseFeeDenominator`:
   ```go
   Kip71GasTarget: {
       Canonicalizer: uint64Canonicalizer,
       FormatChecker: func(cv any) bool {
           v, ok := cv.(uint64)
           return ok && v > 0
       },
       ...
   },
   ``` [1](#0-0) 

2. **Short term:** Add a defensive guard inside `NextMagmaBlockBaseFee` for `gasTarget == 0`, consistent with the existing guard for `BaseFeeDenominator == 0`:
   ```go
   if kc.GasTarget == 0 {
       gasTarget = 1  // or return lowerBoundBaseFee
   }
   ``` [7](#0-6) 

3. **Long term:** Add cross-parameter invariant checks (e.g., `LowerBoundBaseFee <= UpperBoundBaseFee`) to `PartialParamSet.Add` or a dedicated `ValidateParamSet` function, and add fuzz/property tests covering all KIP-71 parameter combinations including boundary values.

### Proof of Concept

1. The governing node calls `governance_vote("kip71.gastarget", 0)`. The vote is accepted because `noopFormatChecker` returns `true` for `uint64(0)`.
2. At the next epoch block `k*epoch`, the vote is ratified and written to `header.Governance`.
3. Starting from block `(k+1)*epoch`, `GetParamSet` returns `GasTarget = 0`.
4. Any block at height `> (k+1)*epoch` where `parent.GasUsed > 0` triggers:
   - `validateHeader` → `VerifyMagmaHeader` → `NextMagmaBlockBaseFee`
   - Inside `NextMagmaBlockBaseFee`: `parentGasUsed > 0 == gasTarget` → enters the `parentGasUsed > gasTarget` branch
   - `x.Div(x, new(big.Int).SetUint64(0))` → **Go runtime panic: integer divide by zero**
5. All nodes crash. The chain halts.

### Citations

**File:** kaiax/gov/param.go (L310-323)
```go
	Kip71BaseFeeDenominator: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(uint64)
			return ok && v != 0
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.BaseFeeDenominator, nil
		},
		DefaultValue: uint64(20),
	},
```

**File:** kaiax/gov/param.go (L324-334)
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
	},
```

**File:** params/kip71_config.go (L58-103)
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

**File:** kaiax/gov/paramset.go (L209-226)
```go
func (p PartialParamSet) Add(name string, value any) error {
	param, ok := Params[ParamName(name)]
	if !ok {
		return ErrInvalidParamName
	}

	cv, err := param.Canonicalizer(value)
	if err != nil {
		return err
	}

	if !param.FormatChecker(cv) {
		return ErrInvalidParamValue
	}

	p[ParamName(name)] = cv
	return nil
}
```
