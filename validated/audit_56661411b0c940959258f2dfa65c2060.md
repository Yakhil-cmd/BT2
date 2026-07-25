### Title
`GasTarget = 0` Governance Vote Causes Division-by-Zero Panic in `NextMagmaBlockBaseFee`, Halting All Nodes - (`params/kip71_config.go`)

---

### Summary

The KIP-71 base-fee calculation function `NextMagmaBlockBaseFee` divides by `GasTarget` without a zero-guard. The governance parameter `kip71.gastarget` uses `noopFormatChecker` (accepts any `uint64`, including `0`) and no consistency check prevents a zero value. A ratified governance vote setting `kip71.gastarget = 0` causes every subsequent call to `NextMagmaBlockBaseFee` — invoked during block validation, block production, and tx-pool reset — to panic with a division-by-zero, halting all honest nodes.

---

### Finding Description

**Missing zero-guard on `GasTarget` in `NextMagmaBlockBaseFee`**

`params/kip71_config.go` lines 100–121 divide by `gasTarget` in both the "gas used above target" and "gas used below target" branches:

```go
// line 100-102 (parentGasUsed > gasTarget branch)
gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← PANIC if gasTarget == 0

// line 118-120 (parentGasUsed < gasTarget branch)
gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← PANIC if gasTarget == 0
```

Go's `(*big.Int).Div` panics when the divisor is zero. The code explicitly handles `BaseFeeDenominator == 0` with a fallback (lines 71–73), but provides no equivalent protection for `GasTarget == 0`.

**Governance accepts `kip71.gastarget = 0` without rejection**

`kaiax/gov/param.go` registers `Kip71GasTarget` with `noopFormatChecker` (always returns `true`), so any `uint64` value — including `0` — passes format validation. The consistency checker in `kaiax/gov/headergov/impl/header.go` lists `Kip71GasTarget` in the pass-through `return nil` branch with no zero-value guard.

**Call sites that panic**

`NextMagmaBlockBaseFee` is called in four production paths:

| File | Context |
|---|---|
| `blockchain/block_validator.go:199` | Header validation for every imported block |
| `work/worker.go:382` | Block production (miner) |
| `blockchain/tx_pool.go:576` | Tx-pool reset on every chain head update |
| `node/cn/gasprice/feehistory.go:112` | Fee history RPC |

---

### Impact Explanation

Once `kip71.gastarget = 0` is ratified and takes effect at `(k+1)*epoch`, every block whose parent had non-zero gas usage triggers the panic. Because `block_validator.go` calls `NextMagmaBlockBaseFee` inside `validateHeader`, all nodes — including honest validators — crash when attempting to validate or import any block with transactions. Block production also crashes in `worker.go`. The result is a **complete chain halt / consensus divergence** on all honest nodes running the affected software.

The corrupted value is the `baseFee` field of every block header after the governance change: it can never be computed or verified, making all subsequent blocks unprocessable.

---

### Likelihood Explanation

In `governance.governancemode = "none"` (any GC member can vote), a single malicious or mistaken GC member can cast the vote. In `"single"` mode the governing node must act. The vote passes all on-chain validation (format check and consistency check both return success for `kip71.gastarget = 0`). The effect is delayed by one epoch (~1 week on mainnet), giving no automatic on-chain rejection. There is no existing guard that would prevent the ratified value from being applied.

---

### Recommendation

1. **Add a zero-guard in `NextMagmaBlockBaseFee`** analogous to the existing `BaseFeeDenominator` guard:
   ```go
   if kc.GasTarget == 0 {
       // fallback: treat as lowerBound (no adjustment)
       return makeEvenByFloor(parentBaseFee)
   }
   ```

2. **Add a non-zero `FormatChecker` for `Kip71GasTarget`** in `kaiax/gov/param.go`:
   ```go
   FormatChecker: func(cv any) bool {
       v, ok := cv.(uint64)
       return ok && v > 0
   },
   ```

3. **Add a consistency check** in `checkConsistency` for `Kip71GasTarget` and `Kip71MaxBlockGasUsedForBaseFee` to reject zero values at vote time.

---

### Proof of Concept

1. In `governance.governancemode = "none"`, any GC member calls `governance_vote("kip71.gastarget", 0)`.
2. The vote is inscribed in `header.Vote`; `NewVoteData` succeeds because `noopFormatChecker` returns `true`; `checkConsistency` returns `nil`.
3. At the next epoch boundary the vote is ratified; `GetParamSet` returns `GasTarget = 0` for all blocks from `(k+1)*epoch` onward.
4. The next block with any transactions causes `block_validator.go:199` → `VerifyMagmaHeader` → `NextMagmaBlockBaseFee` to execute `x.Div(x, new(big.Int).SetUint64(0))`.
5. Go runtime panics: `runtime error: integer divide by zero` (or `big.Int` internal panic). All nodes crash. Chain halts.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

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

**File:** blockchain/block_validator.go (L195-202)
```go
	if v.config.IsMagmaForkEnabled(header.Number) {
		// Skip governance-dependent validation when gov module is not registered.
		if v.mGov != nil {
			govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
			if err := govParamSet.ToKip71Config().VerifyMagmaHeader(header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
				return err
			}
		}
```

**File:** blockchain/tx_pool.go (L574-577)
```go
	if pool.rules.IsMagma {
		pset := pool.govModule.GetParamSet(newHead.Number.Uint64() + 1)
		pool.gasPrice = pset.ToKip71Config().NextMagmaBlockBaseFee(newHead.Number, newHead.BaseFee, newHead.GasUsed)
		if pool.rules.IsOsaka {
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
