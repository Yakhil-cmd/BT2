### Title
Governance vote for `kip71.gastarget = 0` causes unrecoverable chain halt via divide-by-zero in `NextMagmaBlockBaseFee` — (`params/kip71_config.go`)

---

### Summary

The `kip71.gastarget` governance parameter uses `noopFormatChecker`, accepting any `uint64` value including zero. If the governing node votes `kip71.gastarget = 0`, the value is accepted without rejection, takes effect at the next epoch boundary, and then causes a Go runtime panic (`big.Int` division by zero) inside `NextMagmaBlockBaseFee` on every subsequent block that has non-zero gas used. Because block preparation and header verification both call this function, every node on the network panics and the chain halts permanently with no on-chain recovery path.

---

### Finding Description

`Kip71GasTarget` is registered in `kaiax/gov/param.go` with `noopFormatChecker`, which unconditionally returns `true` for any canonicalized value: [1](#0-0) 

By contrast, the adjacent `Kip71BaseFeeDenominator` parameter explicitly guards against zero: [2](#0-1) 

When a vote for `kip71.gastarget = 0` is cast, `NewVoteData` calls `param.FormatChecker(cv)` which returns `true` for `noopFormatChecker`, so the vote is stored and propagated: [3](#0-2) 

The consistency check in `checkConsistency` also returns `nil` for `IstanbulEpoch` and `Kip71GasTarget` without any range validation: [4](#0-3) 

Once the epoch boundary passes and the parameter takes effect, every call to `NextMagmaBlockBaseFee` with any non-zero `parentGasUsed` reaches the division: [5](#0-4) 

Specifically, at line 102: `y := x.Div(x, new(big.Int).SetUint64(gasTarget))` — Go's `big.Int.Div` panics with "division by zero" when the divisor is zero. The guard at line 71–76 only protects `BaseFeeDenominator`, not `GasTarget`.

`NextMagmaBlockBaseFee` is invoked in two critical paths:

1. **Block preparation** (`blockchain/chain_makers.go` line 306): `header.BaseFee = chain.Config().Governance.KIP71.NextMagmaBlockBaseFee(...)` — the proposer panics before sealing.
2. **Header verification** (`params/kip71_config.go` line 50): `VerifyMagmaHeader` calls `NextMagmaBlockBaseFee` — every validator panics when importing the next block. [6](#0-5) 

The same class of bug exists for `IstanbulEpoch` (also `noopFormatChecker`): setting epoch to 0 causes integer divide-by-zero in `PrevEpochStart` (`blockNum%epoch`) and in `PrepareHeader`/`VerifyGov` (`header.Number.Uint64()%h.epoch`): [7](#0-6) [8](#0-7) [9](#0-8) 

---

### Impact Explanation

Once `kip71.gastarget = 0` takes effect, every block with non-zero gas used causes a Go runtime panic in all nodes simultaneously. Block production stops, block import stops, and the chain halts. There is no on-chain mechanism to recover: the only fix requires a coordinated out-of-band node restart with a patched binary or a manual state override. All KAIA transfers, bridged-asset settlements, and reward distributions are frozen for the duration of the outage. This matches the allowed impact: **consensus divergence on honest nodes** and **invalid block acceptance halting canonical execution**.

---

### Likelihood Explanation

`kip71.gastarget` is explicitly listed as a **mutable** governance parameter in the module README. In `governance.governancemode = "single"` (Kaia Mainnet), the single governing node can cast this vote unilaterally. The vote passes `FormatChecker` and `checkConsistency` without any rejection. The risk is accidental misconfiguration (e.g., a tooling bug encoding the value as bytes that decode to 0) or a compromised governing-node key. The inconsistency with `Kip71BaseFeeDenominator` (which does check `v != 0`) shows the zero-guard was intentionally applied to the denominator but forgotten for the gas target.

---

### Recommendation

1. Replace `noopFormatChecker` for `Kip71GasTarget` with a check that rejects zero:
   ```go
   FormatChecker: func(cv any) bool {
       v, ok := cv.(uint64)
       return ok && v > 0
   },
   ```
2. Apply the same fix to `IstanbulEpoch` (also `noopFormatChecker`; epoch=0 causes identical divide-by-zero panics in `PrevEpochStart`, `PrepareHeader`, and `VerifyGov`).
3. Add a defensive guard inside `NextMagmaBlockBaseFee` analogous to the existing `BaseFeeDenominator == 0` guard (lines 71–76), returning `lowerBoundBaseFee` if `gasTarget == 0`.

---

### Proof of Concept

1. Deploy a Kaia node with `governance.governancemode = "single"`.
2. From the governing node, cast a header governance vote: `kip71.gastarget = 0`.
3. Wait for the epoch boundary; the governance field is written into the epoch block header and accepted by all nodes (no rejection at `VerifyVote` or `VerifyGov`).
4. On the next block where `parentGasUsed > 0`, every node calls `NextMagmaBlockBaseFee` → `x.Div(x, new(big.Int).SetUint64(0))` → Go runtime panic: `"runtime error: invalid memory address or nil pointer dereference"` / `big.Int` internal panic.
5. All nodes crash. The chain halts. No further blocks can be produced or imported until nodes are restarted with a patched binary.

### Citations

**File:** kaiax/gov/param.go (L282-292)
```go
	IstanbulEpoch: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Istanbul == nil {
				return nil, errors.New("istanbul is not set")
			}
			return c.Istanbul.Epoch, nil
		},
		DefaultValue: uint64(604800),
	},
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

**File:** kaiax/gov/headergov/vote.go (L39-54)
```go
	cv, err := param.Canonicalizer(value)
	if err != nil {
		logger.Error("Canonicalize error", "name", name, "value", value, "err", err)
		return nil
	}

	if !param.FormatChecker(cv) {
		logger.Error("Format check error", "name", name, "value", value)
		return nil
	}

	return &voteData{
		voter: voter,
		name:  gov.ParamName(name),
		value: cv,
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L40-53)
```go

	// if epoch block & vote exists in the last epoch, put Governance field.
	if header.Number.Uint64()%h.epoch == 0 {
		gov := h.getExpectedGovernance(header.Number.Uint64())
		if len(gov.Items()) > 0 {
			govBytes, err := gov.ToGovBytes()
			if err != nil {
				return err
			}
			header.Governance = govBytes
			logger.Debug("Prepare header with governance", "num", header.Number.Uint64(), "governance", hexutil.Encode(header.Governance))
		}
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

**File:** kaiax/gov/headergov/impl/getter.go (L72-80)
```go
func PrevEpochStart(blockNum, epoch uint64, isKore bool) uint64 {
	if blockNum <= epoch {
		return 0
	}
	if !isKore {
		blockNum -= 1
	}
	return blockNum - blockNum%epoch - epoch
}
```
