### Title
Missing Lower-Bound Check on `kip71.gastarget` Governance Parameter Causes Panic in `NextMagmaBlockBaseFee`, Halting All Honest Nodes — (`params/kip71_config.go`)

### Summary

The `kip71.gastarget` governance parameter has no lower-bound format check (`noopFormatChecker`). A governing node can vote it to `0`. Once ratified, every subsequent call to `NextMagmaBlockBaseFee` panics on integer division by zero, crashing all honest nodes during block validation and halting the chain.

### Finding Description

`Kip71GasTarget` is registered in `kaiax/gov/param.go` with `FormatChecker: noopFormatChecker`, meaning any `uint64` value — including `0` — passes validation: [1](#0-0) 

By contrast, `Kip71BaseFeeDenominator` explicitly rejects zero: [2](#0-1) 

`checkConsistency` in `headergov/impl/header.go` lists `gov.Kip71GasTarget` in the "no additional checks" branch, so no cross-parameter guard catches a zero value either: [3](#0-2) 

Once the vote is ratified, `NextMagmaBlockBaseFee` uses `gasTarget` as a divisor in two places: [4](#0-3) [5](#0-4) 

`big.Int.Div` panics on a zero divisor. The only safe path is `parentGasUsed == gasTarget` (both zero), which requires an empty block — an extremely rare condition on a live network. Any block with `parentGasUsed > 0` triggers the panic.

`NextMagmaBlockBaseFee` is called from the consensus-critical `validateHeader` path on every Magma-era block: [6](#0-5) 

`BaseFeeDenominator == 0` has a runtime fallback guard (set to 64), but `GasTarget == 0` has no such guard: [7](#0-6) 

### Impact Explanation

Every honest node panics when calling `validateHeader` on any block whose parent had non-zero gas usage. The chain halts. No new blocks can be validated or produced. This is a consensus divergence / chain halt affecting all honest nodes.

### Likelihood Explanation

In `single` governance mode (Mainnet and Kairos), the governing node must cast the vote. In `none` mode, any GC member can. The vote passes all existing format and consistency checks without error. The effect is deferred by one epoch (~1 week on Mainnet), giving no immediate signal that the chain will halt.

### Recommendation

Add a non-zero lower-bound check to `Kip71GasTarget`'s `FormatChecker`, mirroring the existing check for `Kip71BaseFeeDenominator`:

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

Additionally, add a defensive guard in `NextMagmaBlockBaseFee` analogous to the `BaseFeeDenominator == 0` guard, to prevent a panic even if an invalid value somehow reaches the function.

### Proof of Concept

1. Governing node calls `governance_vote("kip71.gastarget", 0)`.
2. Vote passes `noopFormatChecker` and `checkConsistency` (no-op branch). It is inscribed in `header.Vote`.
3. At the next epoch block, the vote is ratified and written to `header.Governance`.
4. Starting from `(k+1)*epoch`, `GetParamSet` returns `GasTarget = 0`.
5. `validateHeader` calls `govParamSet.ToKip71Config().VerifyMagmaHeader(...)` → `NextMagmaBlockBaseFee(...)`.
6. With any `parentGasUsed > 0`: `parentGasUsed > gasTarget` (0) is true; execution reaches `x.Div(x, new(big.Int).SetUint64(0))`.
7. Go runtime panics: `runtime error: integer divide by zero` (via `big.Int.Div`).
8. All nodes crash on every subsequent block. Chain halts.

### Citations

**File:** kaiax/gov/param.go (L310-315)
```go
	Kip71BaseFeeDenominator: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(uint64)
			return ok && v != 0
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

**File:** params/kip71_config.go (L100-103)
```go
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
