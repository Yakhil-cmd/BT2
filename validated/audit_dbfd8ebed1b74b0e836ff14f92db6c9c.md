### Title
Division-by-Zero Panic in `NextMagmaBlockBaseFee` When `GasTarget` Is Governanced to Zero — (`params/kip71_config.go`)

---

### Summary

`NextMagmaBlockBaseFee` in `params/kip71_config.go` divides by `GasTarget` without guarding against zero. The `BaseFeeDenominator == 0` case is explicitly handled with a fallback, but `GasTarget == 0` is not. Because the governance parameter `kip71.gastarget` uses `noopFormatChecker` (no minimum-value validation), a valid governance vote can set it to zero. Once active, every block with non-zero gas usage triggers a `big.Int.Div` panic inside `NextMagmaBlockBaseFee`, which is called on every block during both header preparation and header verification. This halts block production and verification on all honest nodes simultaneously.

---

### Finding Description

`NextMagmaBlockBaseFee` computes the next block's base fee using the formula:

```
baseFeeDelta = parentBaseFee * (parentGasUsed - gasTarget) / gasTarget / baseFeeDenominator
```

The code explicitly guards `BaseFeeDenominator == 0`:

```go
// params/kip71_config.go lines 70-76
var baseFeeDenominator *big.Int
if kc.BaseFeeDenominator == 0 {
    // To avoid panic, set the fluctuation range small
    baseFeeDenominator = new(big.Int).SetUint64(64)
} else {
    baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
}
``` [1](#0-0) 

But `GasTarget` receives no such guard. When `parentGasUsed > 0` (any gas was consumed) and `gasTarget == 0`, the condition `parentGasUsed > gasTarget` is true and execution reaches:

```go
// params/kip71_config.go lines 100-103
gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← panic: division by zero
baseFeeDelta := math.BigMax(x.Div(y, baseFeeDenominator), common.Big1)
``` [2](#0-1) 

The same unguarded division exists in the decreasing-fee branch:

```go
// params/kip71_config.go lines 118-121
gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← panic: division by zero
baseFeeDelta := x.Div(y, baseFeeDenominator)
``` [3](#0-2) 

The governance parameter `kip71.gastarget` is declared with `noopFormatChecker`, meaning any `uint64` value — including `0` — passes validation:

```go
// kaiax/gov/param.go lines 324-334
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,
    ...
    DefaultValue: uint64(30000000),
},
``` [4](#0-3) 

The `checkConsistency` function in `headergov/impl/header.go` adds cross-parameter checks for `LowerBoundBaseFee` and `UpperBoundBaseFee`, but has no check for `GasTarget`:

```go
// kaiax/gov/headergov/impl/header.go lines 205-211
case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, ...,
    gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
    ...
    return nil   // ← no validation for GasTarget == 0
``` [5](#0-4) 

`NextMagmaBlockBaseFee` is called in two critical paths:

1. **Block preparation** — `makeHeader` in `blockchain/chain_makers.go`: [6](#0-5) 

2. **Header verification** — `VerifyMagmaHeader` in `params/kip71_config.go`: [7](#0-6) 

A panic in either path crashes the node process.

---

### Impact Explanation

Once `kip71.gastarget = 0` takes effect (at the start of the next epoch after ratification), every block with non-zero gas usage causes a runtime panic in `NextMagmaBlockBaseFee`. Because this function is called during both block production and block import/verification, all honest nodes crash simultaneously when they attempt to process the first non-empty block. This constitutes a **consensus halt** — an invalid state where no new blocks can be produced or accepted, equivalent to a network-wide denial of service affecting all KAIA transfers, staking operations, and bridge settlements.

---

### Likelihood Explanation

In `none` governance mode, any single GC member can cast the decisive vote for `kip71.gastarget = 0` (the last vote in the epoch wins). In `single` governance mode (Mainnet), the governing node must cast the vote. The trigger is a valid, accepted governance transaction — not an exploit of a cryptographic primitive or external service. The inconsistency between the handled `BaseFeeDenominator == 0` case and the unhandled `GasTarget == 0` case indicates this is an oversight rather than intentional behavior.

---

### Recommendation

1. Add a zero-guard for `GasTarget` in `NextMagmaBlockBaseFee`, mirroring the existing `BaseFeeDenominator` guard:

```go
gasTarget := kc.GasTarget
if gasTarget == 0 {
    // Avoid division by zero; treat as if gas usage equals target
    return makeEvenByFloor(parentBaseFee)
}
```

2. Add a `FormatChecker` for `Kip71GasTarget` that rejects zero:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v > 0
    },
    ...
},
```

3. Add a `checkConsistency` case for `Kip71GasTarget` to reject zero values at vote time.

---

### Proof of Concept

1. In `none` governance mode, a GC member calls `governance_vote("kip71.gastarget", 0)`. The vote passes `noopFormatChecker` and `checkConsistency` without error.
2. At the next epoch boundary, the ratified value `GasTarget = 0` takes effect.
3. The next block with any transactions (non-zero `parentGasUsed`) triggers `NextMagmaBlockBaseFee`.
4. Since `parentGasUsed > 0 == gasTarget`, the `parentGasUsed > gasTarget` branch is taken.
5. `x.Div(x, new(big.Int).SetUint64(0))` panics with a runtime division-by-zero error.
6. All nodes crash simultaneously when attempting to produce or verify this block.
7. The network halts; no KAIA transfers, staking rewards, or bridge operations can proceed.

### Citations

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

**File:** blockchain/chain_makers.go (L305-307)
```go
	if chain.Config().IsMagmaForkEnabled(header.Number) {
		header.BaseFee = chain.Config().Governance.KIP71.NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
	}
```
