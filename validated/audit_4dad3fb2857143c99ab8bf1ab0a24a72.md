### Title
Zero `kip71.gastarget` Governance Vote Accepted Without Validation, Causing Division-by-Zero Panic in `NextMagmaBlockBaseFee` and Chain Halt — (`params/kip71_config.go`, `kaiax/gov/param.go`)

---

### Summary

The `kip71.gastarget` governance parameter accepts a zero value through the header-governance vote path because its `FormatChecker` is `noopFormatChecker`. Once ratified, any subsequent block with non-zero gas used causes a Go runtime panic (`division by zero`) inside `NextMagmaBlockBaseFee`, crashing every node on the network. The developer explicitly guarded the analogous `kip71.basefeedenominator` parameter against zero (both a non-zero `FormatChecker` and a runtime fallback), but applied no equivalent protection to `kip71.gastarget`.

---

### Finding Description

**Root cause 1 — no format check on `Kip71GasTarget`**

In `kaiax/gov/param.go`, `Kip71BaseFeeDenominator` has a `FormatChecker` that rejects zero:

```go
Kip71BaseFeeDenominator: {
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0          // zero explicitly rejected
    },
``` [1](#0-0) 

`Kip71GasTarget` immediately below uses `noopFormatChecker`, which always returns `true`, so `uint64(0)` passes:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // accepts any uint64, including 0
``` [2](#0-1) 

**Root cause 2 — `checkConsistency` skips `Kip71GasTarget`**

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` explicitly lists `Kip71GasTarget` in the "no more checks here" catch-all and returns `nil`:

```go
case gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
    ...
    return nil
``` [3](#0-2) 

**Panic site — `NextMagmaBlockBaseFee`**

`params/kip71_config.go` guards `BaseFeeDenominator == 0` with an explicit comment "To avoid panic":

```go
if kc.BaseFeeDenominator == 0 {
    // To avoid panic, set the fluctuation range small
    baseFeeDenominator = new(big.Int).SetUint64(64)
}
``` [4](#0-3) 

No equivalent guard exists for `GasTarget`. When `GasTarget = 0` and `parentGasUsed > 0` (which is true for virtually every block, since `MaxBlockGasUsedForBaseFee` defaults to 60,000,000), execution enters the "increase" branch and divides by zero:

```go
gasTarget := kc.GasTarget                                    // == 0
parentGasUsed := min(parentHeaderGasUsed, upperGasLimit)     // > 0
// parentGasUsed > gasTarget → enters increase branch
y := x.Div(x, new(big.Int).SetUint64(gasTarget))             // PANIC: division by zero
``` [5](#0-4) 

Go's `(*big.Int).Div` panics unconditionally when the divisor is zero. This panic propagates through `VerifyMagmaHeader` (called during block header verification) and crashes the node process.

---

### Impact Explanation

Once the ratified `GasTarget = 0` takes effect at the next epoch boundary, every node on the network panics when it attempts to verify or produce the first block with non-zero gas used. Because virtually every real block consumes gas, the chain halts immediately and permanently until the software is patched and redeployed. This is a **consensus divergence / chain halt on all honest nodes**, matching the allowed impact gate.

The corrupted governance state value is `ParamSet.GasTarget = 0`, stored in the in-memory history and persisted to the header-governance DB, causing `NextMagmaBlockBaseFee` to produce a fatal panic on every subsequent call.

---

### Likelihood Explanation

In `none` governance mode (supported by the codebase and used in non-mainnet deployments), any single GC member can cast the last vote in an epoch for `kip71.gastarget = 0`. No majority collusion is required. The vote passes `NewVoteData` (noopFormatChecker), passes `VerifyVote` / `checkConsistency` (returns nil), and is ratified at the epoch boundary. The chain halts on the very next block with non-zero gas used — which is essentially every block in practice.

---

### Recommendation

1. **Add a non-zero `FormatChecker` for `Kip71GasTarget`** in `kaiax/gov/param.go`, mirroring the existing check for `Kip71BaseFeeDenominator`:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0
    },
```

2. **Add a runtime guard in `NextMagmaBlockBaseFee`** in `params/kip71_config.go`, consistent with the existing `BaseFeeDenominator` guard:

```go
if gasTarget == 0 {
    gasTarget = kc.MaxBlockGasUsedForBaseFee // or a safe fallback
}
```

3. **Add `Kip71GasTarget` to `checkConsistency`** with an explicit non-zero check, rather than leaving it in the silent catch-all.

---

### Proof of Concept

**Step 1**: In a network running `governance.governancemode = "none"`, any GC member calls:
```
governance_vote("kip71.gastarget", 0)
```

**Step 2**: `NewVoteData` succeeds — `noopFormatChecker` returns `true` for `uint64(0)`. [6](#0-5) 

**Step 3**: `VerifyVote` → `checkConsistency` returns `nil` for `Kip71GasTarget`. [3](#0-2) 

**Step 4**: At the next epoch block, the vote is ratified. `GetParamSet` now returns `GasTarget = 0`.

**Step 5**: The next block arrives with `parentHeaderGasUsed = 21000` (a single transfer). `NextMagmaBlockBaseFee` is called:
```
gasTarget     = 0
upperGasLimit = 60_000_000   (default MaxBlockGasUsedForBaseFee)
parentGasUsed = min(21000, 60_000_000) = 21000
// 21000 > 0 → increase branch
y := x.Div(x, new(big.Int).SetUint64(0))   // runtime panic: integer divide by zero
``` [7](#0-6) 

**Step 6**: Every node crashes. The chain halts. The `VerifyMagmaHeader` call that triggered the panic returns nothing — the block cannot be verified or produced. [8](#0-7)

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

**File:** params/kip71_config.go (L77-103)
```go
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
