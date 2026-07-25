### Title
Missing Zero-Value Guard on `kip71.gastarget` Governance Parameter Causes Division-by-Zero in Base Fee Calculation — (`kaiax/gov/param.go` / `params/kip71_config.go`)

---

### Summary

The `Kip71GasTarget` governance parameter uses `noopFormatChecker`, accepting any `uint64` value including `0`. If a GC member (in `none` governance mode) votes to set `kip71.gastarget = 0`, the value passes all validation and takes effect at the next epoch. Every subsequent block with non-zero gas usage then causes `NextMagmaBlockBaseFee` to panic with a division-by-zero, permanently breaking base-fee computation, block verification, and consensus on all honest nodes.

---

### Finding Description

**Root cause — missing boundary check in the format checker:**

`Kip71GasTarget` is registered with `noopFormatChecker`, which unconditionally returns `true`: [1](#0-0) 

Compare this with `Kip71BaseFeeDenominator`, which correctly rejects zero: [2](#0-1) 

The `checkConsistency` function in `VerifyVote` also performs no cross-check on `Kip71GasTarget`: [3](#0-2) 

So a governance vote `("kip71.gastarget", 0)` passes every validation gate and is ratified at the next epoch boundary.

**Downstream division-by-zero in `NextMagmaBlockBaseFee`:**

Once `GasTarget = 0` is active, every call to `NextMagmaBlockBaseFee` with `parentGasUsed > 0` reaches: [4](#0-3) 

`new(big.Int).SetUint64(gasTarget)` is `0`, so `x.Div(x, 0)` panics (Go's `math/big.Div` panics on a zero divisor). The same divisor appears in the decreasing-fee branch: [5](#0-4) 

The existing zero-guard in the same function covers only `BaseFeeDenominator`, not `GasTarget`: [6](#0-5) 

This asymmetry is the direct analog of the Olympus `wallSpread_ > 10000` vs. `wallSpread_ >= 10000` off-by-one: the setter allows an extreme value that a downstream arithmetic expression cannot handle.

**Vote acceptance path:**

`VerifyMagmaHeader` calls `NextMagmaBlockBaseFee` for every block after the Magma fork: [7](#0-6) 

A panic here propagates through block header verification, crashing or stalling every honest node that tries to import or produce a block.

---

### Impact Explanation

After `kip71.gastarget = 0` takes effect:

- `NextMagmaBlockBaseFee` panics on every block whose parent had non-zero gas usage.
- `VerifyMagmaHeader` (called during block import and proposal) propagates the panic.
- Block production and block import both halt on all honest nodes.
- This is an **invalid block/proof acceptance failure and consensus divergence** on honest nodes — a protected-state impact under the Kaia Allowed Impact Gate.

---

### Likelihood Explanation

- In **`none` governance mode** (the default value per `DefaultValue: "none"` in `param.go`), any GC member can cast the decisive vote. A single malicious or compromised validator is sufficient.
- In **`single` governance mode** (Mainnet), only the governing node can vote, raising the bar to a compromised governing node.
- The vote requires no special transaction crafting — it is a standard `governance_vote("kip71.gastarget", 0)` API call.
- The effect is permanent until a corrective vote is ratified (which itself requires a full epoch and a functioning chain — a chicken-and-egg problem once block production has halted).

---

### Recommendation

Apply the same non-zero guard to `Kip71GasTarget` that already exists for `Kip71BaseFeeDenominator`:

```go
// kaiax/gov/param.go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
-   FormatChecker: noopFormatChecker,
+   FormatChecker: func(cv any) bool {
+       v, ok := cv.(uint64)
+       return ok && v != 0
+   },
    ...
},
```

Additionally, add a defensive zero-guard in `NextMagmaBlockBaseFee` (analogous to the existing `BaseFeeDenominator` guard) so that a misconfigured genesis or a pre-fix chain cannot panic:

```go
// params/kip71_config.go
gasTarget := kc.GasTarget
if gasTarget == 0 {
    gasTarget = kc.MaxBlockGasUsedForBaseFee // or any safe non-zero fallback
}
```

---

### Proof of Concept

1. Deploy a Kaia node with `governance.governancemode = "none"` (the default).
2. As any GC member, call:
   ```
   governance_vote("kip71.gastarget", 0)
   ```
3. Wait for the epoch boundary. The vote is ratified; `GasTarget = 0` takes effect.
4. Submit any transaction. The next block will have `parentGasUsed > 0`.
5. `NextMagmaBlockBaseFee` is called with `gasTarget = 0` and `parentGasUsed > 0`:
   - `parentGasUsed > gasTarget` → true
   - `x.Div(x, new(big.Int).SetUint64(0))` → **panic: runtime error: integer divide by zero**
6. Block production and import halt on all honest nodes. The chain is permanently stalled until a corrective governance vote can be ratified — which itself requires a functioning chain.

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

**File:** params/kip71_config.go (L71-76)
```go
	if kc.BaseFeeDenominator == 0 {
		// To avoid panic, set the fluctuation range small
		baseFeeDenominator = new(big.Int).SetUint64(64)
	} else {
		baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
	}
```

**File:** params/kip71_config.go (L99-103)
```go
		// baseFeeDelta = max(1, parentBaseFee * (parentGasUsed - gasTarget) / gasTarget / baseFeeDenominator)
		gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := math.BigMax(x.Div(y, baseFeeDenominator), common.Big1)
```

**File:** params/kip71_config.go (L117-121)
```go
		// baseFeeDelta = parentBaseFee * (gasTarget - parentGasUsed) / gasTarget / baseFeeDenominator
		gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
		baseFeeDelta := x.Div(y, baseFeeDenominator)
```
