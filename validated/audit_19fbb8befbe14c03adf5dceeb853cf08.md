### Title
Governance vote of `kip71.gastarget = 0` accepted without validation causes division-by-zero panic in `NextMagmaBlockBaseFee`, halting block production and validation — (`params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter uses `noopFormatChecker`, accepting any value including zero. After such a vote takes effect, every call to `NextMagmaBlockBaseFee` for a block with non-zero gas usage divides by `gasTarget = 0`, causing a Go runtime panic. This crashes block production (`commitNewWork`) and block validation (`VerifyMagmaHeader`) on all nodes, halting the chain for any block containing transactions.

---

### Finding Description

`Kip71GasTarget` is registered in `kaiax/gov/param.go` with `noopFormatChecker`, which accepts any `uint64` value including zero: [1](#0-0) 

By contrast, `Kip71BaseFeeDenominator` explicitly rejects zero: [2](#0-1) 

The `NextMagmaBlockBaseFee` function in `params/kip71_config.go` guards against `BaseFeeDenominator == 0` with a fallback: [3](#0-2) 

But no equivalent guard exists for `GasTarget`. When `gasTarget == 0` and `parentGasUsed > 0` (any block with transactions), execution falls into the `parentGasUsed > gasTarget` branch and performs:

```go
y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // gasTarget == 0 → panic
``` [4](#0-3) 

The same panic occurs in the `parentGasUsed < gasTarget` branch: [5](#0-4) 

The `checkConsistency` function in header governance also performs no additional check for `Kip71GasTarget`, returning `nil` unconditionally: [6](#0-5) 

---

### Impact Explanation

`NextMagmaBlockBaseFee` is called in two critical paths:

1. **Block production** — `work/worker.go:382` calls it inside `commitNewWork()`. A panic here crashes the proposer node process. [7](#0-6) 

2. **Block validation** — `VerifyMagmaHeader` calls it to verify the `baseFee` field of every incoming block. A panic here crashes any node attempting to import a block with transactions. [8](#0-7) 

After the governance change takes effect (next epoch boundary), every block containing at least one transaction triggers the panic. The chain can only continue with empty blocks — a practical denial of service. The corrupted protected state is the `kip71.gastarget` value stored in governance, which permanently breaks `NextMagmaBlockBaseFee` for all non-empty blocks.

---

### Likelihood Explanation

In `none` governance mode (any GC member can vote), any validator can cast this vote. In `single` mode (Mainnet), the governing node must act. The vote passes all format and consistency checks because `noopFormatChecker` is used and `checkConsistency` returns `nil` for `Kip71GasTarget`. The parameter change takes effect at the next epoch boundary with no further validation. The developer was clearly aware of the `GasTarget`-as-divisor risk (the `BaseFeeDenominator` zero-guard comment reads "To avoid panic"), making the omission for `GasTarget` a direct oversight.

---

### Recommendation

1. **Short term**: Add a non-zero `FormatChecker` for `Kip71GasTarget`, mirroring `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0
    },
    ...
}
```

2. **Short term**: Add a defensive zero-guard in `NextMagmaBlockBaseFee` for `gasTarget`, analogous to the existing `baseFeeDenominator` guard:

```go
if gasTarget == 0 {
    gasTarget = 1 // or return lowerBoundBaseFee
}
```

3. **Long term**: Audit all `noopFormatChecker` parameters that are used as divisors in block-critical arithmetic paths.

---

### Proof of Concept

1. In `none` governance mode, a GC member casts a vote: `governance_vote("kip71.gastarget", 0)`.
2. The vote passes `VerifyVote` (format check is `noopFormatChecker`, consistency check returns `nil`).
3. At the next epoch boundary, the ratified value `gastarget = 0` is written to governance state.
4. Starting from `(epoch+1)*epoch` block, `GetParamSet` returns `GasTarget = 0`.
5. `commitNewWork` calls `pset.ToKip71Config().NextMagmaBlockBaseFee(...)`. If the parent block used any gas, `parentGasUsed > 0 == gasTarget`, entering the `parentGasUsed > gasTarget` branch.
6. `x.Div(x, new(big.Int).SetUint64(0))` panics: `runtime error: integer divide by zero`.
7. The proposer node crashes. Every other node attempting to validate a non-empty block also panics via `VerifyMagmaHeader`.
8. The chain halts for all blocks with transactions. [9](#0-8) [1](#0-0)

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
