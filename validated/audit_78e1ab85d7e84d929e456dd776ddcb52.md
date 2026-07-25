### Title
`kip71.gastarget` Governance Parameter Accepts Zero with No Lower-Bound Guard, Causing Division-by-Zero Panic in Base Fee Calculation on All Nodes — (File: `params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter is registered with `noopFormatChecker`, meaning any `uint64` value — including `0` — passes validation and can be ratified on-chain. `NextMagmaBlockBaseFee()` uses `gasTarget` as an integer divisor in two branches but has **no zero-guard for `GasTarget`**, even though an identical guard already exists for `BaseFeeDenominator`. When `GasTarget == 0` and any block carries non-zero gas usage (the normal case on a live network), every call to `NextMagmaBlockBaseFee()` panics with an integer division-by-zero, crashing every honest node that attempts to validate or produce a block.

---

### Finding Description

**Root cause — missing lower-bound in `FormatChecker`:**

`kip71.gastarget` is declared in `kaiax/gov/param.go` with `noopFormatChecker`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // accepts ANY uint64, including 0
    DefaultValue:  uint64(30000000),
},
``` [1](#0-0) 

`noopFormatChecker` unconditionally returns `true`:

```go
func noopFormatChecker(cv any) bool {
    return true
}
``` [2](#0-1) 

The `checkConsistency()` function in header governance also performs no cross-parameter check for `Kip71GasTarget`:

```go
case gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee, ...:
    return nil
``` [3](#0-2) 

**Root cause — missing zero-guard in `NextMagmaBlockBaseFee()`:**

The function guards `BaseFeeDenominator == 0` explicitly but has **no equivalent guard for `GasTarget`**:

```go
var baseFeeDenominator *big.Int
if kc.BaseFeeDenominator == 0 {
    // To avoid panic, set the fluctuation range small
    baseFeeDenominator = new(big.Int).SetUint64(64)
} else {
    baseFeeDenominator = new(big.Int).SetUint64(kc.BaseFeeDenominator)
}
gasTarget := kc.GasTarget   // ← no zero-guard here
``` [4](#0-3) 

When `parentGasUsed > gasTarget` (i.e., `parentGasUsed > 0` when `gasTarget == 0`):

```go
gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← PANIC: division by zero
``` [5](#0-4) 

The same division appears in the `else` branch (gas below target):

```go
gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← PANIC: division by zero
``` [6](#0-5) 

**Reachability — called on every Magma+ block:**

`VerifyMagmaHeader()` calls `NextMagmaBlockBaseFee()` and is invoked by `validateHeader()` for every block after the Magma fork:

```go
govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
if err := govParamSet.ToKip71Config().VerifyMagmaHeader(
    header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
    return err
}
``` [7](#0-6) 

The same function is also called during block production in `work/worker.go`:

```go
nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(
    parent.Number(), parent.Header().BaseFee, parent.GasUsed())
``` [8](#0-7) 

And in the gas-price oracle (`node/cn/gasprice/gasprice.go` line 334). Every code path that touches base-fee computation panics simultaneously.

---

### Impact Explanation

Once the ratified `kip71.gastarget = 0` takes effect (at the start of the next epoch), every honest node panics with an unrecovered integer division-by-zero on the first block whose parent had non-zero gas usage. Because `validateHeader` is called during sync, import, and block production, **all nodes crash simultaneously and cannot recover without a software patch or a corrective governance vote**. This constitutes persistent consensus divergence / chain halt on all honest nodes — within the allowed impact gate ("invalid block/proof/snapshot acceptance, or consensus divergence on honest nodes").

---

### Likelihood Explanation

The trigger requires the governing node (a semi-trusted, single privileged actor in Mainnet's `single` governance mode) to cast a vote for `kip71.gastarget = 0`. This could occur through operator misconfiguration (e.g., passing `0` instead of a gas-target value in units of gas), a tooling bug, or a compromised governing key. The absence of any validation — while an identical guard already exists for `BaseFeeDenominator` — makes an accidental misconfiguration plausible. The impact is catastrophic and irreversible without an out-of-band fix.

---

### Recommendation

1. **Add a lower-bound `FormatChecker` for `Kip71GasTarget`** in `kaiax/gov/param.go`, requiring the value to be strictly greater than zero (analogous to how `GovernanceDeriveShaImpl` is bounded to `<= 2`).

2. **Add a zero-guard in `NextMagmaBlockBaseFee()`** in `params/kip71_config.go`, mirroring the existing `BaseFeeDenominator` guard:
   ```go
   if kc.GasTarget == 0 {
       // Governance misconfiguration: treat as no-change to avoid panic
       return makeEvenByFloor(parentBaseFee)
   }
   gasTarget := kc.GasTarget
   ```

3. **Add a consistency check** in `checkConsistency()` (`kaiax/gov/headergov/impl/header.go`) to reject votes that would set `kip71.gastarget` to zero.

---

### Proof of Concept

```
1. Governing node calls:
   governance_vote("kip71.gastarget", 0)

2. The vote passes FormatChecker (noopFormatChecker → true).
   checkConsistency returns nil for Kip71GasTarget.
   The vote is inscribed in header.Vote.

3. At the next epoch block, the vote is ratified and written to header.Governance.
   From the following epoch onward, GetParamSet() returns GasTarget = 0.

4. On the first block N where parent.GasUsed > 0:
   validateHeader(N) →
     govParamSet.ToKip71Config().VerifyMagmaHeader(...) →
       NextMagmaBlockBaseFee(parent.Number, parent.BaseFee, parent.GasUsed) →
         parentGasUsed = min(parent.GasUsed, upperGasLimit) > 0
         parentGasUsed > gasTarget (0)  → enters "gas above target" branch
         x.Div(x, new(big.Int).SetUint64(0))  → PANIC: integer divide by zero

5. All nodes crash. Chain halts.
```

### Citations

**File:** kaiax/gov/param.go (L160-162)
```go
func noopFormatChecker(cv any) bool {
	return true
}
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

**File:** blockchain/block_validator.go (L197-202)
```go
		if v.mGov != nil {
			govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
			if err := govParamSet.ToKip71Config().VerifyMagmaHeader(header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
				return err
			}
		}
```

**File:** work/worker.go (L382-383)
```go
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
```
