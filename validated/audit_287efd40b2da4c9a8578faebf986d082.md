### Title
Per-Vote KIP-71 Bound Validation Allows Two Governance Votes to Invert `LowerBoundBaseFee > UpperBoundBaseFee`, Permanently Corrupting the Magma Base Fee Mechanism - (`kaiax/gov/headergov/impl/header.go`)

### Summary

The `checkConsistency` function validates `kip71.lowerboundbasefee` and `kip71.upperboundbasefee` votes individually against the **current** parameter set, but never checks the ordering constraint between two pending votes in the same epoch. In `none` governance mode, two GC members can independently cast votes that each pass validation but together produce `LowerBoundBaseFee > UpperBoundBaseFee` after ratification. This permanently corrupts `NextMagmaBlockBaseFee`, which is enforced by `VerifyMagmaHeader` on every block, causing all transactions to pay incorrect fees and breaking the fee market.

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` performs per-vote checks:

```go
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) > params.UpperBoundBaseFee {   // checks against CURRENT upper
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)
    if vote.Value().(uint64) < params.LowerBoundBaseFee {   // checks against CURRENT lower
        return ErrUpperBoundBaseFee
    }
```

Each vote is validated against the **current ratified** parameter set, not against other pending votes in the same epoch. The `getExpectedGovernance` function at epoch end simply collects all last-votes-per-parameter and ratifies them without any cross-parameter ordering check:

```go
for _, voteBlock := range sortedVoteBlocks {
    vote := prevEpochVotes[voteBlock]
    govs.Add(string(vote.Name()), vote.Value())   // no ordering invariant enforced
}
```

**Attack path (none mode, two GC members):**

| Step | Actor | Vote | `checkConsistency` result |
|------|-------|------|--------------------------|
| 1 | GC member A | `LowerBoundBaseFee = 500 Gwei` | passes: `500 ≤ 750` (current upper) |
| 2 | GC member B | `UpperBoundBaseFee = 100 Gwei` | passes: `100 ≥ 25` (current lower) |
| 3 | Epoch end | both ratified | `Lower = 500 Gwei`, `Upper = 100 Gwei` |

After ratification, `NextMagmaBlockBaseFee` in `params/kip71_config.go` receives inverted bounds:

```go
lowerBoundBaseFee := new(big.Int).SetUint64(500_000_000_000)  // 500 Gwei
upperBoundBaseFee := new(big.Int).SetUint64(100_000_000_000)  // 100 Gwei
makeEvenByCeil(lowerBoundBaseFee)   // 500 Gwei
makeEvenByFloor(upperBoundBaseFee)  // 100 Gwei

// Clamping logic is now inverted:
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {   // true for any fee ≥ 100 Gwei
    parentBaseFee = upperBoundBaseFee             // clamps DOWN to 100 Gwei
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 { // true for fee < 100 Gwei
    parentBaseFee = lowerBoundBaseFee             // clamps UP to 500 Gwei
}
```

With `parentBaseFee` clamped to 100 Gwei (the "upper" bound):
- If `parentGasUsed < gasTarget`: fee decreases, but `nextBaseFee < lowerBoundBaseFee (500 Gwei)` → returns 500 Gwei
- If `parentGasUsed > gasTarget`: fee increases, but capped at `upperBoundBaseFee (100 Gwei)`

The base fee oscillates between 100 Gwei and 500 Gwei with **inverted** market signals — high gas usage drives the fee toward 100 Gwei (the "ceiling"), low gas usage drives it toward 500 Gwei (the "floor"). `VerifyMagmaHeader` enforces this corrupted value on every block:

```go
govParamSet := v.mGov.GetParamSet(header.Number.Uint64())
if err := govParamSet.ToKip71Config().VerifyMagmaHeader(
    header.BaseFee, parent.Number, parent.BaseFee, parent.GasUsed); err != nil {
    return err
}
```

All nodes compute the same corrupted expected base fee and reject any block that does not match it. The corruption persists until a corrective governance vote is ratified (one full epoch, up to 604,800 blocks / ~1 week on Mainnet).

Additionally, `kip71.gastarget` and `kip71.maxblockgasusedforbasefee` have **no cross-parameter validation at all** (`noopFormatChecker`, no `checkConsistency` case), so a single GC member in `none` mode can vote `GasTarget > MaxBlockGasUsedForBaseFee`, permanently pinning the base fee at `LowerBoundBaseFee` (fee can never increase since `min(actualGasUsed, MaxBlockGasUsedForBaseFee) < GasTarget` always).

### Impact Explanation

- **Fee corruption**: Every transaction on the network pays an incorrect base fee — either too high or too low — for up to one full epoch.
- **Inverted fee market**: High network congestion drives fees down; low usage drives fees up. The EIP-1559-style mechanism is permanently inverted.
- **Block validity enforcement**: `VerifyMagmaHeader` enforces the corrupted base fee. Any block with the "correct" (pre-corruption) base fee is rejected by all nodes. This is an invalid-state-acceptance impact: the chain accepts blocks whose base fee violates the intended economic invariant.
- **KAIA fee accounting**: Fees burned or distributed to validators are computed from the corrupted base fee, directly affecting KAIA token economics.

### Likelihood Explanation

In `none` governance mode, any GC member can cast a vote. Two members independently voting for conflicting bound values — even accidentally — produces this state. Each individual vote passes all existing validation. There is no warning, no atomic check, and no ratification-time guard. The epoch window (up to 604,800 blocks) gives ample time for two such votes to coexist. In `single` mode (Mainnet/Kairos), the governing node would need to cast both votes intentionally, which is a privileged scenario.

### Recommendation

**Short term**: Add a cross-parameter ordering check at ratification time in `getExpectedGovernance` (or in `VerifyGov`) to reject any epoch governance object where the ratified `LowerBoundBaseFee ≥ UpperBoundBaseFee` or `GasTarget > MaxBlockGasUsedForBaseFee`.

**Long term**: Extend `checkConsistency` to inspect pending votes in the current epoch for the same parameter pair, so that a vote for `LowerBoundBaseFee` also checks against any already-pending `UpperBoundBaseFee` vote in the same epoch (and vice versa). Add `FormatChecker` cross-validation for `GasTarget` vs `MaxBlockGasUsedForBaseFee`.

### Proof of Concept

**Setup**: `none` governance mode, current params: `LowerBoundBaseFee = 25 Gwei`, `UpperBoundBaseFee = 750 Gwei`, `GasTarget = 30M`, `MaxBlockGasUsedForBaseFee = 60M`.

1. GC member A calls `governance_vote("kip71.lowerboundbasefee", 500_000_000_000)` at block 100.
   - `checkConsistency`: `500e9 > 750e9`? No → **passes**.
2. GC member B calls `governance_vote("kip71.upperboundbasefee", 100_000_000_000)` at block 200.
   - `checkConsistency`: `100e9 < 25e9`? No → **passes**.
3. At epoch block (e.g., block 604800), `getExpectedGovernance` collects both votes and ratifies: `{LowerBoundBaseFee: 500e9, UpperBoundBaseFee: 100e9}`. No ordering check is performed.
4. From block 604801 onward, `GetParamSet` returns `LowerBoundBaseFee = 500 Gwei > UpperBoundBaseFee = 100 Gwei`.
5. `NextMagmaBlockBaseFee` clamps `parentBaseFee` to 100 Gwei (inverted upper), then returns 500 Gwei when gas usage is low (inverted lower). The expected base fee oscillates with inverted market signals.
6. `VerifyMagmaHeader` enforces the corrupted value. Any block with a "correct" base fee is rejected. All nodes accept blocks with the corrupted base fee.
7. All transactions pay incorrect fees. The fee market is broken for the entire next epoch.

**Corrupted values**:
- `header.BaseFee` on every block from epoch `k+1` onward is computed from inverted bounds.
- Fee revenue distributed/burned per block is incorrect by up to `|500 Gwei − 100 Gwei| × blockGasUsed` KAIA per block. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L179-192)
```go
	case gov.Kip71LowerBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) > params.UpperBoundBaseFee {
			return ErrLowerBoundBaseFee
		} else {
			return nil
		}
	case gov.Kip71UpperBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) < params.LowerBoundBaseFee {
			return ErrUpperBoundBaseFee
		} else {
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

**File:** kaiax/gov/headergov/impl/header.go (L218-233)
```go
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
	prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
	prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
	govs := make(gov.PartialParamSet)

	sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
	slices.Sort(sortedVoteBlocks)

	for _, voteBlock := range sortedVoteBlocks {
		vote := prevEpochVotes[voteBlock]
		govs.Add(string(vote.Name()), vote.Value())
	}

	// assert(len(headergov.NewGovData(govs).Items()) == len(govs))
	return headergov.NewGovData(govs)
}
```

**File:** params/kip71_config.go (L58-86)
```go
func (kc *KIP71Config) NextMagmaBlockBaseFee(parentHeaderNumber *big.Int, parentHeaderBaseFee *big.Int, parentHeaderGasUsed uint64) *big.Int {
	// governance parameters
	lowerBoundBaseFee := new(big.Int).SetUint64(kc.LowerBoundBaseFee)
	upperBoundBaseFee := new(big.Int).SetUint64(kc.UpperBoundBaseFee)
	makeEvenByCeil(lowerBoundBaseFee)
	makeEvenByFloor(upperBoundBaseFee)

	// If the parent is the magma disabled block or genesis, then return the lowerBoundBaseFee (default 25ston)
	if parentHeaderNumber.Cmp(new(big.Int).SetUint64(0)) == 0 || parentHeaderBaseFee == nil {
		return makeEvenByFloor(lowerBoundBaseFee)
	}

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

**File:** kaiax/gov/param.go (L335-366)
```go
	Kip71LowerBoundBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.LowerBoundBaseFee, nil
		},
		DefaultValue: uint64(25000000000),
	},
	Kip71MaxBlockGasUsedForBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.MaxBlockGasUsedForBaseFee, nil
		},
		DefaultValue: uint64(60000000),
	},
	Kip71UpperBoundBaseFee: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.KIP71 == nil {
				return nil, errors.New("kip71 is not set")
			}
			return c.Governance.KIP71.UpperBoundBaseFee, nil
		},
		DefaultValue: uint64(750000000000),
```
