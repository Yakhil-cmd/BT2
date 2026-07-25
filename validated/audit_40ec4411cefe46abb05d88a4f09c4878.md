### Title
Missing Zero-Value Guard on `Kip71GasTarget` Governance Parameter Enables Chain-Halting Division-by-Zero — (`kaiax/gov/param.go` / `params/kip71_config.go`)

---

### Summary

The `Kip71GasTarget` governance parameter uses `noopFormatChecker` (always returns `true`), so a governance vote setting it to `0` passes all validation. When the vote takes effect, every subsequent call to `NextMagmaBlockBaseFee` with any non-zero `parentGasUsed` performs an integer division by zero (`big.Int.Div` with a zero divisor panics in Go), crashing every node that attempts to validate or produce the next block and permanently halting the chain.

---

### Finding Description

**Root cause — missing zero check in `FormatChecker`:**

`Kip71GasTarget` is defined in `kaiax/gov/param.go` with `FormatChecker: noopFormatChecker`, which unconditionally returns `true`: [1](#0-0) 

Compare this with `Kip71BaseFeeDenominator`, which has an explicit non-zero guard: [2](#0-1) 

`Kip71GasTarget` is not in `AlwaysDeprecated` or `PermissionlessDeprecated`, so it remains a live, voteable parameter: [3](#0-2) 

**No consistency check either:**

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` lists `Kip71GasTarget` in the catch-all `return nil` branch — no additional validation is performed: [4](#0-3) 

**Division-by-zero in `NextMagmaBlockBaseFee`:**

`params/kip71_config.go` has a defensive zero-check for `BaseFeeDenominator` but has **no equivalent guard for `GasTarget`**: [5](#0-4) 

When `GasTarget == 0` and `parentGasUsed > 0` (the normal case on a live network), execution reaches: [6](#0-5) 

`new(big.Int).SetUint64(0)` as the divisor causes `big.Int.Div` to panic unconditionally. The same division appears in the decreasing-fee branch: [7](#0-6) 

`NextMagmaBlockBaseFee` is called from `VerifyMagmaHeader`, which is on the critical block-validation path: [8](#0-7) 

---

### Impact Explanation

Once the epoch containing the `GasTarget = 0` vote closes and the governance change is committed to `header.Governance`, every node — proposer and validator alike — calls `NextMagmaBlockBaseFee` to compute or verify the next block's `BaseFee`. With `parentGasUsed > 0` (virtually guaranteed on mainnet), the division by zero panics, crashing the node process. Because the panic occurs deterministically on every node processing that block, the chain halts permanently. No honest node can advance past that block number.

**Corrupted value:** `header.BaseFee` is never computed; the block is never finalized. All pending KAIA transfers, reward distributions, and state transitions in that block and all subsequent blocks are permanently blocked.

---

### Likelihood Explanation

In `governance.governancemode = "none"`, any council member who becomes the block proposer can embed this vote in a block header. The vote passes `VerifyVote` (voter is in council, voter is the proposer, `FormatChecker` is a no-op, `checkConsistency` returns nil). It takes effect at the next epoch boundary — a predictable, observable event. A single malicious or compromised council member is sufficient; no collusion is required.

In `governance.governancemode = "single"`, the governing node alone can trigger this. If the governing node key is compromised, the same outcome follows.

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
    ...
},
```

2. **Add a defensive runtime guard in `NextMagmaBlockBaseFee`** in `params/kip71_config.go`, analogous to the existing `BaseFeeDenominator` guard:

```go
if gasTarget == 0 {
    gasTarget = 1 // or return lowerBoundBaseFee as a safe fallback
}
```

3. **Add a `checkConsistency` case for `Kip71GasTarget`** in `kaiax/gov/headergov/impl/header.go` to reject zero at vote-verification time.

---

### Proof of Concept

1. Run a Magma-enabled Kaia network in `governance.governancemode = "none"`.
2. As the block proposer for block `N`, embed a governance vote `kip71.gastarget = 0` in `header.Vote`.
3. `VerifyVote` accepts the vote: `noopFormatChecker` returns `true`; `checkConsistency` returns `nil`.
4. At epoch block `N + epoch`, the vote is ratified into `header.Governance` and written to the governance store.
5. For block `N + epoch + 1`, every node calls `NextMagmaBlockBaseFee(parentNum, parentBaseFee, parentGasUsed)` where `parentGasUsed > 0`.
6. `parentGasUsed > gasTarget (= 0)` → execution reaches `x.Div(x, new(big.Int).SetUint64(0))` → **panic: integer divide by zero**.
7. All nodes crash. The chain does not advance past block `N + epoch`.

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

**File:** kaiax/gov/param.go (L561-582)
```go
// AlwaysDeprecated is the definitive list of params that are always deprecated
// regardless of fork state.
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

// PermissionlessDeprecated lists params that become disallowed for voting
// after the Permissionless hardfork. Validator membership is governed by
// AddressBookV2 (KIP-290) and the committee is derived from on-chain state,
// so these governance levers no longer have an effect.
var PermissionlessDeprecated = map[ParamName]struct{}{
	AddValidator:          {},
	RemoveValidator:       {},
	IstanbulCommitteeSize: {},
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
