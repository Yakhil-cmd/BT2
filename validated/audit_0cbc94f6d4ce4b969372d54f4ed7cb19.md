### Title
`kip71.gastarget` Governance Parameter Accepts Zero, Causing Division-by-Zero Panic and Chain Halt in `NextMagmaBlockBaseFee` — (`params/kip71_config.go`)

---

### Summary

The mutable governance parameter `kip71.gastarget` (`GasTarget`) has no minimum-value guard in either its `FormatChecker` or in `NextMagmaBlockBaseFee`. Setting it to `0` via a governance vote causes a `big.Int` division-by-zero panic in every subsequent call to `NextMagmaBlockBaseFee`, which is invoked on every block during header verification. The result is a permanent chain halt: all honest nodes crash when they attempt to import any block produced after the governance change takes effect.

---

### Finding Description

**Root cause — missing lower-bound guard on `Kip71GasTarget`**

In `kaiax/gov/param.go`, `Kip71GasTarget` is declared with `noopFormatChecker`, meaning any `uint64` value — including `0` — passes validation:

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: noopFormatChecker,   // ← accepts 0
    ...
    DefaultValue: uint64(30000000),
},
``` [1](#0-0) 

By contrast, `Kip71BaseFeeDenominator` — which is also used as a divisor — explicitly rejects `0` in its `FormatChecker` **and** has a runtime zero-guard in `NextMagmaBlockBaseFee`:

```go
Kip71BaseFeeDenominator: {
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v != 0   // ← explicit zero rejection
    },
``` [2](#0-1) 

```go
if kc.BaseFeeDenominator == 0 {
    // To avoid panic, set the fluctuation range small
    baseFeeDenominator = new(big.Int).SetUint64(64)
``` [3](#0-2) 

No equivalent guard exists for `GasTarget`. In `NextMagmaBlockBaseFee`, `gasTarget` is used as a divisor at two points:

```go
gasTarget := kc.GasTarget
...
if parentGasUsed == gasTarget {
    return makeEvenByFloor(parentBaseFee)   // only safe exit when both are 0
} else if parentGasUsed > gasTarget {
    gasUsedDelta := new(big.Int).SetUint64(parentGasUsed - gasTarget)
    x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
    y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← panics when gasTarget == 0
``` [4](#0-3) 

```go
    gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
    x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
    y := x.Div(x, new(big.Int).SetUint64(gasTarget))   // ← panics when gasTarget == 0
``` [5](#0-4) 

Go's `math/big.(*Int).Div` panics with a run-time division-by-zero when the divisor is `0`.

**`kip71.gastarget` is a mutable governance parameter**

The governance README explicitly lists `kip71.gastarget` as mutable (changeable via `governance_vote`): [6](#0-5) 

The `checkConsistency` function in `headergov` performs no additional validation for `Kip71GasTarget` — it simply returns `nil`: [7](#0-6) 

**`NextMagmaBlockBaseFee` is called on every block during verification**

`VerifyMagmaHeader` calls `NextMagmaBlockBaseFee` and is invoked from `blockchain/block_validator.go`, `blockchain/tx_pool.go`, and `work/worker.go`: [8](#0-7) 

---

### Impact Explanation

Once `GasTarget = 0` takes effect (at the start of the next epoch), every block with `parentGasUsed > 0` triggers the panic path. Because `parentGasUsed = min(actualGasUsed, MaxBlockGasUsedForBaseFee)` and `MaxBlockGasUsedForBaseFee` defaults to 60 million, any block that executes at least one transaction has `parentGasUsed > 0 = gasTarget`, entering the `parentGasUsed > gasTarget` branch and panicking at `x.Div(x, new(big.Int).SetUint64(0))`.

All honest nodes crash when they attempt to import the first non-empty block after the governance change. The chain halts permanently. There is no in-protocol recovery path — a new governance vote to restore `GasTarget` cannot be processed because block import itself is broken.

**Corrupted value:** `header.BaseFee` can never be computed or verified again; the canonical execution path for every post-change block is broken.

---

### Likelihood Explanation

**Impact:** High — permanent chain halt affecting all nodes.

**Likelihood:** Low — requires the governing node (a semi-trusted, designated governance authority) to cast a vote of `kip71.gastarget = 0`. The risk is analogous to the external report: the protocol trusts a privileged actor but provides no minimum-bound guard to prevent a catastrophic misconfiguration. The inconsistency is made concrete by the fact that the codebase already applies both a `FormatChecker` guard and a runtime zero-guard for `BaseFeeDenominator` — the same protection is simply absent for `GasTarget`.

---

### Recommendation

1. **Add a `FormatChecker` minimum bound for `Kip71GasTarget`** (reject `0`, analogous to `Kip71BaseFeeDenominator`):

```go
Kip71GasTarget: {
    Canonicalizer: uint64Canonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(uint64)
        return ok && v > 0   // reject zero
    },
    ...
},
``` [1](#0-0) 

2. **Add a runtime zero-guard in `NextMagmaBlockBaseFee`** (defensive, matching the `BaseFeeDenominator` pattern):

```go
gasTarget := kc.GasTarget
if gasTarget == 0 {
    gasTarget = DefaultGasTarget  // or return lowerBoundBaseFee
}
``` [9](#0-8) 

---

### Proof of Concept

1. **Cast the vote** (governing node, `single` mode):
   ```
   governance_vote("kip71.gastarget", 0)
   ```
   The vote passes `noopFormatChecker` and `checkConsistency` returns `nil`. [10](#0-9) 

2. **Vote is ratified** at the next epoch block and `GasTarget = 0` takes effect from `(k+1)*epoch`. [11](#0-10) 

3. **First non-empty block** after the change: `parentGasUsed > 0`, so `parentGasUsed > gasTarget (0)` is true. Execution reaches:
   ```go
   y := x.Div(x, new(big.Int).SetUint64(0))  // runtime panic: division by zero
   ``` [12](#0-11) 

4. **All nodes crash.** `VerifyMagmaHeader` → `NextMagmaBlockBaseFee` is on the critical path for every block import (`block_validator.go`, `tx_pool.go`, `worker.go`). The chain halts permanently.

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

**File:** params/kip71_config.go (L71-73)
```go
	if kc.BaseFeeDenominator == 0 {
		// To avoid panic, set the fluctuation range small
		baseFeeDenominator = new(big.Int).SetUint64(64)
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

**File:** params/kip71_config.go (L118-120)
```go
		gasUsedDelta := new(big.Int).SetUint64(gasTarget - parentGasUsed)
		x := new(big.Int).Mul(parentBaseFee, gasUsedDelta)
		y := x.Div(x, new(big.Int).SetUint64(gasTarget))
```

**File:** kaiax/gov/README.md (L17-34)
```markdown
```
<mutable parameters>
governance.deriveshaimpl
governance.governingnode
governance.govparamcontract
governance.unitprice
istanbul.committeesize
kip71.basefeedenominator
kip71.gastarget
kip71.lowerboundbasefee
kip71.maxblockgasusedforbasefee
kip71.upperboundbasefee
reward.kip82ratio
reward.mintingamount
reward.ratio
reward.stakingrewardthreshold
reward.useflexreward

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

**File:** kaiax/gov/headergov/impl/api.go (L53-82)
```go
func (api *headerGovAPI) Vote(name string, value any) (string, error) {
	var (
		voter     = api.h.nodeAddress
		nextBlock = api.h.Chain.CurrentBlock().NumberU64() + 1
		gp        = api.h.GetParamSet(nextBlock)
		gMode     = gp.GovernanceMode
	)

	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}

	vote := headergov.NewVoteData(voter, name, value)
	if vote == nil {
		return "", ErrInvalidKeyValue
	}

	if gov.DeprecatedAt(vote.Name(), api.h.ChainConfig.Rules(new(big.Int).SetUint64(nextBlock))) {
		return "", ErrDeprecatedVote
	}

	err := api.h.checkConsistency(nextBlock, vote)
	if err != nil {
		return "", err
	}

	// TODO-kaiax: add removevalidator vote check

	api.h.PushMyVotes(vote)
	return "(kaiax) Your vote is prepared. It will be put into the block header or applied when your node generates a block as a proposer. Note that your vote may be duplicate.", nil
```

**File:** kaiax/gov/headergov/README.md (L38-50)
```markdown
At every epoch block (i.e., `k*epoch` blocks), the node that becomes the proposer will check if the vote has been ratified.
If the vote is ratified, the node will announce the ratification in the block header `header.Governance`.
In other words, `header.Governance` can contain data only at epoch blocks.
If there are no votes in an epoch, the next starting block of the epoch will have an empty `header.Governance`.
It contains a JSON object of `{name: value}` for each ratified parameter.

The ratification condition is determined by the `governance.governancemode` parameter. Mainnet and Kairos both operate in `single` mode. There are two governance modes:

- `none` mode: all members of the GC can vote. For each governance parameter, the last vote in the epoch will be ratified.
- `single` mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified in block order. For each governance parameter, the last vote in the epoch will be ratified.

Parameter change ratified at `k*epoch` block takes effect starting from `(k+1)*epoch` block.
It is worth noting that the effective time of the ratification is `(k+1)*epoch + 1` before Kore.
```
