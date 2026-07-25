### Title
Governance vote of `kip71.gastarget = 0` causes division-by-zero panic in `NextMagmaBlockBaseFee`, halting all nodes — (`params/kip71_config.go`)

---

### Summary

The governance parameter `kip71.gastarget` (`Kip71GasTarget`) accepts zero as a valid value because its `FormatChecker` is `noopFormatChecker`. When `GasTarget = 0` takes effect, every subsequent block with non-zero gas usage triggers an integer division-by-zero panic inside `NextMagmaBlockBaseFee`, crashing all nodes that attempt to produce or validate blocks. The sister parameter `kip71.basefeedenominator` is explicitly protected against zero both at the format-check layer and with a runtime fallback, demonstrating that the developers were aware of the risk but omitted the same protection for `GasTarget`.

---

### Finding Description

**Vulnerable parameter definition** — `kaiax/gov/param.go`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // ← accepts any value, including 0
    ...
    DefaultValue: uint64(30000000),
},
``` [1](#0-0) 

Compare with the protected sibling:

```go
Kip71BaseFeeDenominator: {
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // ← explicitly rejects 0
    },
    ...
},
``` [2](#0-1) 

**Runtime fallback exists for `BaseFeeDenominator` but not for `GasTarget`** — `params/kip71_config.go`:

```go
if kc.BaseFeeDenominator == 0 {
    // To avoid panic, set the fluctuation range small
    baseFeeDenominator = new(big.Int).SetUint64(64)
} else {
    baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
}
gasTarget := kc.GasTarget   // ← no zero-guard here
``` [3](#0-2) 

**Division-by-zero crash** — when `gasTarget = 0` and `parentGasUsed > 0`, the condition `parentGasUsed > gasTarget` is true and execution reaches:

```go
gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // ← PANIC: division by zero
``` [4](#0-3) 

The same division appears in the `else` branch (line 120) for the case where `parentGasUsed < gasTarget`, but that branch is unreachable when `gasTarget = 0` and `parentGasUsed > 0`.

**Call sites that crash** — `NextMagmaBlockBaseFee` is invoked on every Magma+ block in all of the following production paths:

| File | Purpose |
|---|---|
| `work/worker.go:382` | Block proposer computing next base fee |
| `blockchain/block_validator.go:199` | All nodes validating incoming blocks |
| `blockchain/tx_pool.go` | Tx pool filtering |
| `blockchain/chain_makers.go:306` | Chain generation | [5](#0-4) [6](#0-5) 

---

### Impact Explanation

Once the governance vote `kip71.gastarget = 0` takes effect, every block that contains at least one transaction (i.e., `parentGasUsed > 0`) causes a Go runtime panic in `NextMagmaBlockBaseFee`. Because this function is called during both block production and block validation, **all honest nodes crash simultaneously**. The chain halts: no new blocks can be proposed or accepted. This is a persistent consensus divergence / chain halt affecting all nodes on the network.

The corrupted value is the `baseFee` field of every block header after the vote takes effect — it can never be computed, so no valid block can be produced or validated.

---

### Likelihood Explanation

In "single" governance mode, the governing node is a semi-trusted entity that could set `kip71.gastarget = 0` by mistake (e.g., a misconfigured governance transaction) or deliberately. The external report's analog explicitly notes that the analogous parameter "could be done by mistake or by the creators of the launch event to exploit it themselves." The inconsistency with `BaseFeeDenominator` — which is protected at both the format-check and runtime levels — makes an accidental omission plausible. The `noopFormatChecker` provides no warning to the operator that 0 is an invalid value.

---

### Recommendation

1. **Add a non-zero format check for `Kip71GasTarget`**, matching the pattern already used for `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0
    },
    ...
},
```

2. **Add a runtime guard in `NextMagmaBlockBaseFee`** as a defense-in-depth fallback, analogous to the existing `BaseFeeDenominator` guard:

```go
gasTarget := kc.GasTarget
if gasTarget == 0 {
    return makeEvenByFloor(lowerBoundBaseFee) // safe fallback
}
``` [7](#0-6) 

---

### Proof of Concept

1. Deploy a Magma-enabled Kaia network in "single" governance mode.
2. The governing node submits a governance vote: `kip71.gastarget = 0`.
3. The vote is accepted (no format check rejects it).
4. After the epoch boundary, the new `GasTarget = 0` takes effect.
5. The next block that includes any transaction (non-zero `parentGasUsed`) triggers:
   - `work/worker.go:382` → `pset.ToKip71Config().NextMagmaBlockBaseFee(...)` → panic in the proposer node.
   - `blockchain/block_validator.go:199` → `govParamSet.ToKip71Config().VerifyMagmaHeader(...)` → `NextMagmaBlockBaseFee(...)` → panic in all validating nodes.
6. All nodes crash. The chain halts permanently until the binary is patched or the governance state is manually corrected. [1](#0-0) [8](#0-7)

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

**File:** params/kip71_config.go (L70-78)
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

**File:** work/worker.go (L378-384)
```go
	if self.config.IsMagmaForkEnabled(nextBlockNum) {
		// NOTE-Kaia NextBlockBaseFee needs the header of parent, self.chain.CurrentBlock
		// So above code, TxPool().Pending(), is separated with this and can be refactored later.
		pset := self.govModule.GetParamSet(nextBlockNum.Uint64())
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
	}
```

**File:** blockchain/block_validator.go (L195-202)
```go
	if v.config.IsMagmaForkEnabled(header.Number) {
		// Skip governance-dependent validation when gov module is not registered.
		if v.mGov != nil {
			govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
			if err := govParamSet.ToKip71Config().VerifyMagmaHeader(header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
				return err
			}
		}
```
