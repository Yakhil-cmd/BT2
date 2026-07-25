### Title
Governance vote for `kip71.gastarget = 0` causes unguarded division-by-zero panic in `NextMagmaBlockBaseFee`, permanently halting block production and KAIA reward distribution — (`params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter accepts any `uint64` value, including `0`, because its `FormatChecker` is `noopFormatChecker`. Once a governance vote ratifying `kip71.gastarget = 0` takes effect, every subsequent block with non-zero gas usage triggers a division-by-zero panic inside `NextMagmaBlockBaseFee`. Unlike `BaseFeeDenominator`, which has an explicit zero-guard in the same function, `GasTarget` has none. The panic crashes every node simultaneously, permanently halting block production, block validation, and all KAIA reward distribution until a hard fork is deployed.

---

### Finding Description

**Step 1 — Faulty value accepted without validation**

`kip71.gastarget` is registered in `Params` with `noopFormatChecker`:

```go
// kaiax/gov/param.go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // accepts any uint64, including 0
    ...
    DefaultValue: uint64(30000000),
},
```

`noopFormatChecker` unconditionally returns `true`:

```go
func noopFormatChecker(cv any) bool {
    return true
}
```

`NewVoteData` calls `FormatChecker` and returns a valid `VoteData` for `kip71.gastarget = 0`. [1](#0-0) [2](#0-1) [3](#0-2) 

**Step 2 — No consistency check blocks the vote**

`checkConsistency` in `headergov/impl/header.go` explicitly lists `gov.Kip71GasTarget` in the "no further checks" branch and returns `nil`:

```go
case gov.GovernanceDeriveShaImpl, ..., gov.Kip71GasTarget, ...:
    return nil
```

`VerifyVote` calls `checkConsistency` and accepts the vote. [4](#0-3) 

**Step 3 — Ratified value propagates into block processing**

After the epoch boundary, `GetParamSet` returns `GasTarget = 0`. Every call site that computes the next base fee reads this value:

```go
// work/worker.go
nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(
    parent.Number(), parent.Header().BaseFee, parent.GasUsed())
``` [5](#0-4) 

**Step 4 — Division-by-zero panic**

Inside `NextMagmaBlockBaseFee`, `BaseFeeDenominator = 0` has an explicit guard, but `GasTarget` does not:

```go
// params/kip71_config.go
var baseFeeDenominator *big.Int
if kc.BaseFeeDenominator == 0 {          // ← guard exists for denominator
    baseFeeDenominator = new(big.Int).SetUint64(64)
} else {
    baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
}
gasTarget := kc.GasTarget               // ← no guard; can be 0
...
} else if parentGasUsed > gasTarget {   // true whenever parentGasUsed > 0
    gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
    x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
    y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // PANIC: divide by zero
```

`big.Int.Div` panics on a zero divisor. The panic is unrecovered and crashes the node process. [6](#0-5) 

**Affected call sites** (all crash):

| File | Call |
|---|---|
| `work/worker.go:382` | block production |
| `blockchain/block_validator.go` | block validation |
| `blockchain/tx_pool.go` | tx pool base-fee filter |
| `node/cn/gasprice/feehistory.go:112` | fee history API |
| `node/cn/gasprice/gasprice.go` | gas price oracle | [7](#0-6) 

---

### Impact Explanation

Once `kip71.gastarget = 0` is ratified and takes effect, every block that contains at least one transaction (non-zero `parentGasUsed`) causes every node to panic and crash. Block production halts. Block validation halts. No new blocks are produced, so no KAIA block rewards are distributed to validators or treasury funds. The chain is permanently halted until a coordinated hard fork overrides the parameter. This satisfies the "invalid state transition / consensus divergence on honest nodes" and "reward distribution affecting KAIA" impact criteria.

---

### Likelihood Explanation

`kip71.gastarget` is listed as a **mutable** governance parameter in `kaiax/gov/README.md` and is not in `AlwaysDeprecated` or `PermissionlessDeprecated`. In `none` governance mode, a single GC member can cast the decisive vote. In `single` mode, the governing node alone can do so. The value `0` is a plausible fat-finger or adversarial input. The effect is delayed by one epoch (604 800 blocks on Mainnet), giving no immediate warning. [8](#0-7) 

---

### Recommendation

1. **Add a non-zero `FormatChecker` for `Kip71GasTarget`**, mirroring the existing check for `Kip71BaseFeeDenominator`:

```go
// kaiax/gov/param.go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // reject zero
    },
    ...
},
``` [9](#0-8) 

2. **Add a defensive zero-guard in `NextMagmaBlockBaseFee`** for `gasTarget`, consistent with the existing guard for `baseFeeDenominator`:

```go
if gasTarget == 0 {
    gasTarget = kc.GasTarget  // already 0; treat as "no adjustment"
    return makeEvenByFloor(parentBaseFee)
}
``` [10](#0-9) 

3. **Add a `checkConsistency` guard** for `Kip71GasTarget` in `headergov/impl/header.go` to reject zero at vote-verification time. [4](#0-3) 

---

### Proof of Concept

1. In `none` governance mode, a GC member calls:
   ```
   governance_vote("kip71.gastarget", 0)
   ```
   `NewVoteData` succeeds (`noopFormatChecker` returns `true`). `checkConsistency` returns `nil`. The vote is inscribed in `header.Vote`.

2. At the next epoch boundary, the vote is ratified. `GetParamSet` now returns `GasTarget = 0` for all subsequent blocks.

3. The next block that includes any transaction has `parentGasUsed > 0`. Every node calls `NextMagmaBlockBaseFee` with `gasTarget = 0`:
   ```
   parentGasUsed (e.g. 21000) > gasTarget (0)  →  enters "increase" branch
   y := x.Div(x, new(big.Int).SetUint64(0))    →  panic: integer divide by zero
   ```

4. The unrecovered panic crashes every node process. Block production and validation stop. All KAIA reward distribution ceases permanently. [11](#0-10) [1](#0-0)

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

**File:** kaiax/gov/param.go (L563-572)
```go
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
```

**File:** kaiax/gov/headergov/vote.go (L44-48)
```go

	if !param.FormatChecker(cv) {
		logger.Error("Format check error", "name", name, "value", value)
		return nil
	}
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
