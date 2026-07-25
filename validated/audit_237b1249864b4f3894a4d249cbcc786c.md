### Title
Unbounded `kip71.gastarget` Governance Parameter Allows Division-by-Zero Panic in `NextMagmaBlockBaseFee`, Halting Chain Consensus — (`params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter is registered with `noopFormatChecker`, accepting any `uint64` value including zero. When a governance vote sets `GasTarget = 0` and any subsequent block contains transactions (gas used > 0), `NextMagmaBlockBaseFee` performs an integer division by zero, causing a runtime panic. This crashes the block producer, the tx pool, and the block validator on every honest node, halting consensus. Notably, the analogous `BaseFeeDenominator == 0` case is explicitly guarded with a fallback, demonstrating awareness of the pattern — but `GasTarget == 0` is left unguarded.

---

### Finding Description

**Missing lower-bound validation on `Kip71GasTarget`:**

In `kaiax/gov/param.go`, the `Kip71GasTarget` parameter entry uses `noopFormatChecker`, which unconditionally returns `true` for any canonicalized value: [1](#0-0) 

`noopFormatChecker` is defined as: [2](#0-1) 

There is also no cross-parameter consistency check for `Kip71GasTarget` in `checkConsistency`: [3](#0-2) 

**Division-by-zero in `NextMagmaBlockBaseFee`:**

When `GasTarget = 0` and `parentGasUsed > 0` (any block with transactions), execution reaches: [4](#0-3) 

`new(big.Int).SetUint64(0)` is a zero `*big.Int`. Go's `math/big` panics on division by zero: `"If y == 0, a division-by-zero run-time panic occurs."` The only escape before this line is the shortcut at line 94–96, which only fires when `parentBaseFee` is already exactly at `upperBoundBaseFee` — not guaranteed in general.

**Contrast with the handled `BaseFeeDenominator == 0` case:**

The code explicitly guards against `BaseFeeDenominator == 0` with a fallback: [5](#0-4) 

No equivalent guard exists for `GasTarget == 0`.

**Call sites that panic:**

The function is called on every block in the miner: [6](#0-5) 

In the tx pool on every head update: [7](#0-6) 

And in block header validation via `VerifyMagmaHeader`: [8](#0-7) 

---

### Impact Explanation

Setting `kip71.gastarget = 0` causes a runtime panic in `NextMagmaBlockBaseFee` on the first block with any gas used. This crashes:
- The block producer (`work/worker.go`) — no new blocks can be proposed
- The tx pool (`blockchain/tx_pool.go`) — no transactions can be accepted
- The block validator (`params/kip71_config.go` via `VerifyMagmaHeader`) — no blocks can be imported

All honest nodes crash simultaneously, producing a consensus divergence / chain halt. This matches the allowed impact: **"Invalid state transition … or consensus divergence on honest nodes."**

---

### Likelihood Explanation

The trigger is a governance vote by the governing node (in `"single"` mode) or a majority of validators (in `"ballot"` mode). The governing node is a semi-trusted actor analogous to the `onlyOwner` role in the external report. The vote passes `NewVoteData` validation (since `noopFormatChecker` accepts 0) and `checkConsistency` (which has no check for `GasTarget`). No additional preconditions are required beyond the governance vote taking effect.

---

### Recommendation

Replace `noopFormatChecker` for `Kip71GasTarget` with a check that enforces a minimum value of 1:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v > 0  // GasTarget must be non-zero to prevent division by zero
    },
    ...
},
```

Similarly, add a zero-guard inside `NextMagmaBlockBaseFee` as a defense-in-depth measure, mirroring the existing `BaseFeeDenominator == 0` guard:

```go
if kc.GasTarget == 0 {
    // Avoid division by zero; treat as if gas used == target
    return makeEvenByFloor(parentBaseFee)
}
```

---

### Proof of Concept

1. Governing node submits a header governance vote: `kip71.gastarget = 0`.
2. `NewVoteData` succeeds — `noopFormatChecker` returns `true` for `uint64(0)`. [1](#0-0) 
3. `checkConsistency` returns `nil` for `Kip71GasTarget` — no bounds check. [3](#0-2) 
4. After the governance epoch, `GetParamSet` returns `GasTarget = 0`.
5. The next block includes any transaction (gas used > 0).
6. `NextMagmaBlockBaseFee` is called from `worker.go` or `tx_pool.go`.
7. `parentGasUsed > 0 = gasTarget` → enters the `else if parentGasUsed > gasTarget` branch.
8. `x.Div(x, new(big.Int).SetUint64(0))` → **runtime panic: integer divide by zero**.
9. All nodes running the Magma fork crash; chain halts.

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

**File:** work/worker.go (L381-383)
```go
		pset := self.govModule.GetParamSet(nextBlockNum.Uint64())
		nextBaseFee = pset.ToKip71Config().NextMagmaBlockBaseFee(parent.Number(), parent.Header().BaseFee, parent.GasUsed())
		pending = types.FilterTransactionWithBaseFee(pending, nextBaseFee)
```

**File:** blockchain/tx_pool.go (L574-577)
```go
	if pool.rules.IsMagma {
		pset := pool.govModule.GetParamSet(newHead.Number.Uint64() + 1)
		pool.gasPrice = pset.ToKip71Config().NextMagmaBlockBaseFee(newHead.Number, newHead.BaseFee, newHead.GasUsed)
		if pool.rules.IsOsaka {
```
