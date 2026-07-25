### Title
Missing Zero-Value Validation for `kip71.gastarget` Governance Parameter Causes Division-by-Zero Panic Halting Block Production and Validation — (`kaiax/gov/param.go` / `params/kip71_config.go`)

---

### Summary

The `Kip71GasTarget` governance parameter is registered with `noopFormatChecker`, which accepts any `uint64` value including `0`. A valid governance vote setting `kip71.gastarget = 0` causes `NextMagmaBlockBaseFee` to perform an integer division by zero (`big.Int.Div` with a zero divisor) whenever any block has non-zero gas usage. This panics the Go runtime, halting block production and block validation on every node simultaneously.

---

### Finding Description

In `kaiax/gov/param.go`, the `Kip71GasTarget` parameter is defined with `noopFormatChecker`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // accepts 0
    ...
    DefaultValue: uint64(30000000),
},
``` [1](#0-0) 

By contrast, `Kip71BaseFeeDenominator` — the other divisor in the same formula — explicitly rejects zero:

```go
Kip71BaseFeeDenominator: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // zero explicitly rejected
    },
    ...
},
``` [2](#0-1) 

In `params/kip71_config.go`, `NextMagmaBlockBaseFee` uses `GasTarget` as a divisor in both the increase and decrease branches:

```go
gasTarget := kc.GasTarget
...
parentGasUsed := min(parentHeaderGasUsed, upperGasLimit)
if parentGasUsed == gasTarget {          // both 0 → early return (safe)
    return makeEvenByFloor(parentBaseFee)
} else if parentGasUsed > gasTarget {    // any gas used > 0 → enters here
    ...
    y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // PANIC: divide by 0
``` [3](#0-2) 

`big.Int.Div` panics on a zero divisor in Go. The `BaseFeeDenominator == 0` case is explicitly handled with a fallback value, but `GasTarget == 0` is not:

```go
if kc.BaseFeeDenominator == 0 {
    baseFeeDenominator = new(big.Int).SetUint64(64)  // fallback
} else {
    baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
}
// No equivalent guard for gasTarget
``` [4](#0-3) 

`NextMagmaBlockBaseFee` is called on every Magma-fork block from three production paths:

- **Block production**: `worker.go` → `pset.ToKip71Config().NextMagmaBlockBaseFee(...)` [5](#0-4) 
- **Block validation**: `VerifyMagmaHeader` → `NextMagmaBlockBaseFee(...)` [6](#0-5) 
- **Fee history RPC**: `processBlock` → `kip71Config.NextMagmaBlockBaseFee(...)` [7](#0-6) 

`Kip71GasTarget` is **not** in `AlwaysDeprecated` and **not** in `PermissionlessDeprecated`, so it remains a live, voteable parameter: [8](#0-7) 

---

### Impact Explanation

Once `kip71.gastarget = 0` is committed to chain state via a governance vote, every subsequent Magma-fork block that includes any transaction (non-zero `parentGasUsed`) causes a Go runtime panic in `NextMagmaBlockBaseFee`. This simultaneously crashes:

- All block-producing nodes (worker loop panics before sealing)
- All validating nodes (header verification panics on import)

The result is a **permanent chain halt** — no node can produce or accept a new block until the binary is patched and restarted with a corrected parameter. This is an invalid state transition / consensus divergence on all honest nodes.

---

### Likelihood Explanation

In `governance.governancemode = "single"` (the Kaia mainnet default), the single governing node can cast this vote unilaterally in one transaction. In `"none"` mode, any validator can vote. The parameter passes all existing validation layers (`uint64Canonicalizer` succeeds for `0`, `noopFormatChecker` returns `true`) and is written to chain state without rejection.

The asymmetry with `BaseFeeDenominator` (which has an explicit `v != 0` guard) confirms this is an oversight rather than intentional design.

---

### Recommendation

Add a non-zero check to the `FormatChecker` for `Kip71GasTarget`, mirroring the existing guard on `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v > 0   // reject zero to prevent division-by-zero
    },
    ...
},
```

Additionally, add a defensive guard in `NextMagmaBlockBaseFee` analogous to the `BaseFeeDenominator` fallback:

```go
if gasTarget == 0 {
    return makeEvenByFloor(lowerBoundBaseFee)
}
```

---

### Proof of Concept

1. Deploy a Magma-fork-enabled Kaia network with `governance.governancemode = "single"`.
2. From the governing node, cast a governance vote: `kip71.gastarget = 0`.
3. Wait for the vote to take effect (next epoch boundary).
4. Submit any transaction to the network (non-zero gas usage).
5. Observe: every node panics in `NextMagmaBlockBaseFee` at `x.Div(x, new(big.Int).SetUint64(0))` — block production and validation halt permanently.

The root cause is the missing `v > 0` guard in `kaiax/gov/param.go` for `Kip71GasTarget`, while the identical divisor protection exists for `Kip71BaseFeeDenominator` in the same file. [9](#0-8) [10](#0-9)

### Citations

**File:** kaiax/gov/param.go (L310-334)
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

**File:** kaiax/gov/param.go (L561-582)
```go
// AlwaysDeprecated is the definitive list of params that are always deprecated
// regardless of fork state.
var AlwaysDeprecated = map[ParamName]struct{}{
	GovernanceGovernanceMode:     {},
	IstanbulEpoch:                {},
	IstanbulPolicy:               {},
	RewardDeferredTxFee:          {},
	RewardMinimumStake:           {},
	RewardProposerUpdateInterval: {},
	RewardStakingUpdateInterval:  {},
	RewardUseGiniCoeff:           {},
}

// PermissionlessDeprecated lists params that become disallowed for voting
// after the Permissionless hardfork. Validator membership is governed by
// AddressBookV2 (KIP-290) and the committee is derived from on-chain state,
// so these governance levers no longer have an effect.
var PermissionlessDeprecated = map[ParamName]struct{}{
	AddValidator:          {},
	RemoveValidator:       {},
	IstanbulCommitteeSize: {},
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

**File:** params/kip71_config.go (L70-103)
```go
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

**File:** work/worker.go (L381-383)
```go
		pset := self.govModule.GetParamSet(nextBlockNum.Uint64())
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
```

**File:** node/cn/gasprice/feehistory.go (L111-113)
```go
	if isNextBlockMagma {
		bf.results.nextBaseFee = kip71Config.NextMagmaBlockBaseFee(bf.header.Number, bf.header.BaseFee, bf.header.GasUsed)
	} else {
```
