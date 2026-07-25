### Title
Division by Zero in `NextMagmaBlockBaseFee` When `GasTarget` Governance Parameter Is Set to Zero — (`params/kip71_config.go`)

### Summary

`NextMagmaBlockBaseFee` divides by `gasTarget` without a zero-guard. The governance parameter `kip71.gastarget` uses `noopFormatChecker`, which accepts any `uint64` value including `0`. If a governance vote sets `GasTarget = 0` and any subsequent block has non-zero gas usage, every call to `NextMagmaBlockBaseFee` panics with a Go integer division-by-zero, halting block production and validation on all nodes.

### Finding Description

In `params/kip71_config.go`, `NextMagmaBlockBaseFee` reads `gasTarget` from the governance parameter set and uses it as a divisor in two branches:

```go
// parentGasUsed > gasTarget branch (line 102)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))

// parentGasUsed < gasTarget branch (line 120)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))
``` [1](#0-0) [2](#0-1) 

The code already handles `BaseFeeDenominator == 0` with an explicit fallback:

```go
if kc.BaseFeeDenominator == 0 {
    baseFeeDenominator = new(big.Int).SetUint64(64)
}
``` [3](#0-2) 

No equivalent guard exists for `GasTarget`. The only early-exit is `if parentGasUsed == gasTarget` (both zero), but if `gasTarget == 0` and any block has `parentGasUsed > 0`, execution falls into the `parentGasUsed > gasTarget` branch and divides by zero.

The governance parameter `Kip71GasTarget` is registered with `noopFormatChecker`, which accepts any `uint64` value including `0`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,
    ...
    DefaultValue: uint64(30000000),
},
``` [4](#0-3) 

The `checkConsistency` function in header governance lists `gov.Kip71GasTarget` as a parameter that passes with format checks only — no additional semantic validation: [5](#0-4) 

### Impact Explanation

`NextMagmaBlockBaseFee` is called in three critical production paths:

1. **Block production** (`work/worker.go` line 382): `pset.ToKip71Config().NextMagmaBlockBaseFee(...)` — the worker panics and cannot produce any new block.
2. **Block validation** (`params/kip71_config.go` line 50 via `VerifyMagmaHeader`): every imported block fails validation with a panic.
3. **Gas price oracle** (`node/cn/gasprice/gasprice.go` line 334): `isRelaxedNetwork` panics. [6](#0-5) [7](#0-6) [8](#0-7) 

The corrupted value is the `baseFee` field of every block header after the governance change takes effect: it can never be computed, so no valid block can be produced or accepted. All honest nodes halt simultaneously, causing a complete consensus failure.

### Likelihood Explanation

In `single` governance mode (the Kaia Mainnet configuration), a single governing node can submit a vote for `kip71.gastarget = 0`. The vote passes format validation (`noopFormatChecker`) and consistency validation (no semantic check for zero). After one epoch, the parameter takes effect. The next block with any non-zero gas usage triggers the panic. This is a single-actor trigger, not majority-validator collusion.

### Recommendation

Add a zero-guard for `GasTarget` in `NextMagmaBlockBaseFee`, mirroring the existing guard for `BaseFeeDenominator`:

```go
gasTarget := kc.GasTarget
if gasTarget == 0 {
    // Avoid division by zero; treat as if gas usage equals target
    return makeEvenByFloor(parentBaseFee)
}
```

Additionally, update the `FormatChecker` for `Kip71GasTarget` in `kaiax/gov/param.go` to reject zero:

```go
FormatChecker: func(cv any) bool {
    v, ok := cv.(uint64)
    return ok && v > 0
},
```

### Proof of Concept

1. In single-governance mode, the governing node submits a vote: `kip71.gastarget = 0`.
2. The vote passes `noopFormatChecker` and `checkConsistency` (no semantic validation).
3. After one epoch, `GetParamSet` returns `GasTarget = 0`.
4. The next block is produced with any non-zero `gasUsed` (e.g., a single transfer).
5. `worker.commitNewWork` calls `pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())`.
6. Inside `NextMagmaBlockBaseFee`: `parentGasUsed > 0 == gasTarget` → enters the `parentGasUsed > gasTarget` branch → `x.Div(x, new(big.Int).SetUint64(0))` → Go runtime panic: `integer divide by zero`.
7. All nodes calling `VerifyMagmaHeader` on the next block also panic.
8. Block production and validation halt on all nodes; the chain stops progressing. [9](#0-8)

### Citations

**File:** params/kip71_config.go (L45-55)
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
```

**File:** params/kip71_config.go (L71-76)
```go
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

**File:** kaiax/gov/headergov/impl/header.go (L205-211)
```go
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
```

**File:** work/worker.go (L381-383)
```go
		pset := self.govModule.GetParamSet(nextBlockNum.Uint64())
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
```

**File:** node/cn/gasprice/gasprice.go (L332-336)
```go
func (oracle *Oracle) isRelaxedNetwork(header *types.Header) bool {
	pset := oracle.govModule.GetParamSet(header.Number.Uint64() + 1)
	nextBaseFee := pset.ToKip71Config().NextMagmaBlockBaseFee(header.Number, header.BaseFee, header.GasUsed)
	return nextBaseFee.Cmp(big.NewInt(int64(pset.LowerBoundBaseFee))) <= 0
}
```
