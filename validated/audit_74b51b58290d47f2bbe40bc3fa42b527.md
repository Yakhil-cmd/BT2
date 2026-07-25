### Title
Unconstrained `kip71.gastarget` Governance Parameter Allows Zero-Value Vote Causing Panic in `NextMagmaBlockBaseFee` — (`params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter uses `noopFormatChecker`, accepting any `uint64` value including zero. When a governance vote sets `GasTarget = 0` and it takes effect, every subsequent call to `NextMagmaBlockBaseFee()` panics with a division-by-zero on `big.Int.Div(x, 0)` whenever the parent block consumed any gas. This halts all nodes that attempt to validate or produce blocks, causing a permanent consensus failure.

---

### Finding Description

**Unconstrained parameter definition** — `kip71.gastarget` is registered with `noopFormatChecker`, which unconditionally returns `true` for any canonical value: [1](#0-0) 

**No consistency check at vote time** — `checkConsistency()` in `VerifyVote` places `gov.Kip71GasTarget` in the "no additional checks" branch, returning `nil` for any value including zero: [2](#0-1) 

**Division-by-zero in base-fee computation** — `NextMagmaBlockBaseFee()` uses `GasTarget` as a divisor in two places. When `parentGasUsed > 0` (any block with transactions) and `GasTarget == 0`, the condition `parentGasUsed > gasTarget` is true and execution reaches:

```go
y := x.Div(x, new(big.Int).SetUint64(gasTarget))  // gasTarget == 0 → panic
``` [3](#0-2) 

Go's `big.Int.Div` panics unconditionally when the divisor is zero. The same path exists in the decreasing-fee branch at line 120.

**`BaseFeeDenominator` is protected but `GasTarget` is not** — The `Kip71BaseFeeDenominator` parameter explicitly rejects zero (`return ok && v != 0`), demonstrating the developers understood the division-by-zero risk for the denominator but omitted the same guard for `GasTarget`: [4](#0-3) 

**Call sites that propagate the panic** — `NextMagmaBlockBaseFee` is called during block validation (`VerifyMagmaHeader`), transaction pool reset, and gas price oracle updates: [5](#0-4) 

---

### Impact Explanation

Once the governance change takes effect (at the start of the epoch following ratification), every block that contains at least one transaction triggers the panic in `NextMagmaBlockBaseFee`. Because this function is called during header verification on every node, all honest nodes crash simultaneously. The chain cannot advance. This constitutes a permanent consensus halt — an invalid state transition that breaks canonical execution across the entire network.

---

### Likelihood Explanation

In `governance.governancemode = "none"` (any council member may vote), a single council member can cast the vote unilaterally; the last vote in the epoch wins. In `"single"` mode (Mainnet), the governing node must cast the vote. Both are semi-trusted actors who are not supposed to be able to halt the chain with a single parameter change. The vote requires no special tooling beyond the standard `governance_vote` JSON-RPC call.

---

### Recommendation

Add a non-zero lower-bound check to the `FormatChecker` for `Kip71GasTarget`, mirroring the existing guard on `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v > 0   // GasTarget must be nonzero (used as divisor)
    },
    ...
},
```

Additionally, add a defensive guard inside `NextMagmaBlockBaseFee` itself:

```go
if gasTarget == 0 {
    return makeEvenByFloor(parentBaseFee)
}
``` [6](#0-5) 

---

### Proof of Concept

1. In `governance.governancemode = "none"`, any council member calls:
   ```json
   {"method":"governance_vote","params":["kip71.gastarget", 0]}
   ```
2. The vote passes `NewVoteData` (noopFormatChecker) and `checkConsistency` (no-op branch).
3. At the next epoch block the vote is ratified; `GetParamSet` returns `GasTarget = 0` from the epoch after that.
4. The first block with `parentGasUsed > 0` causes every node to call `NextMagmaBlockBaseFee` with `GasTarget = 0`.
5. `parentGasUsed > 0 == gasTarget` → enters the `parentGasUsed > gasTarget` branch → `big.Int.Div(x, big.NewInt(0))` → **panic: division by zero**.
6. All nodes crash; the chain halts permanently until operators manually patch and restart with a corrected genesis or governance override. [7](#0-6) [1](#0-0) [2](#0-1)

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

**File:** params/kip71_config.go (L77-78)
```go
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

**File:** blockchain/tx_pool.go (L574-580)
```go
	if pool.rules.IsMagma {
		pset := pool.govModule.GetParamSet(newHead.Number.Uint64() + 1)
		pool.gasPrice = pset.ToKip71Config().NextMagmaBlockBaseFee(newHead.Number, newHead.BaseFee, newHead.GasUsed)
		if pool.rules.IsOsaka {
			pool.blobBaseFee = params.CalcBlobFee(pool.gasPrice)
		}
	}
```
