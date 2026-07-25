### Title
Missing Non-Negative Range Check on `reward.mintingamount` Governance Parameter Causes Permanent Chain Halt — (File: `kaiax/gov/param.go`)

---

### Summary

The `RewardMintingAmount` governance parameter is declared with `FormatChecker: noopFormatChecker`, which unconditionally accepts any value. The `bigIntCanonicalizer` accepts negative `*big.Int` values from string input. Because `RewardMintingAmount` is not in `AlwaysDeprecated`, a GC member (in `"none"` governance mode) can vote for a negative minting amount. Once ratified, every subsequent block's `FinalizeState` call produces negative per-address reward entries, which are caught by `RewardSpec.Validate()`, causing `FinalizeState` to return `ErrNegativeRewardAmount` and permanently halting the chain.

---

### Finding Description

**Root cause — `kaiax/gov/param.go`:**

`RewardMintingAmount` is registered with `FormatChecker: noopFormatChecker`, which always returns `true`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: noopFormatChecker,   // ← no range check
    ...
}
``` [1](#0-0) 

`noopFormatChecker` is defined as:

```go
func noopFormatChecker(cv any) bool {
    return true
}
``` [2](#0-1) 

`bigIntCanonicalizer` accepts any decimal string, including negative ones (`"-9600000000000000000"` → `*big.Int` with `Sign() == -1`): [3](#0-2) 

`RewardMintingAmount` is **not** in `AlwaysDeprecated`, so it remains voteable: [4](#0-3) 

The `checkConsistency` function in `VerifyVote` returns `nil` for `RewardMintingAmount` with no additional check: [5](#0-4) 

**Propagation — `kaiax/reward/impl/getter.go`:**

Once ratified, `GetParamSet` returns the negative `MintingAmount`. In `getDeferredRewardSimple`, the proposer reward is computed as `minted + execFee`. With a large negative minting amount (e.g., `-9.6e18`), the proposer reward is negative for any realistic fee level: [6](#0-5) 

In `getDeferredRewardFullKore` / `getDeferredRewardFullFlex`, `RewardRatio.Split(negativeMintingAmount)` produces negative `kif`, `kef`, `kpf`, and `validators` values, which are added to `spec.Rewards` via `IncRecipient`: [7](#0-6) 

**Chain halt — `kaiax/reward/spec.go` + `kaiax/reward/impl/blockstate.go`:**

`RewardSpec.Validate()` checks every per-address reward entry and returns `ErrNegativeRewardAmount` if any is negative:

```go
func (spec *RewardSpec) Validate() error {
    for addr, amount := range spec.Rewards {
        if amount.Sign() < 0 {
            return errNegativeRewardAmount(addr, amount)
        }
    }
    return nil
}
``` [8](#0-7) 

`FinalizeState` calls `spec.Validate()` before applying rewards. If it returns an error, `FinalizeState` returns that error, making every block invalid:

```go
spec, err := r.GetDeferredReward(header, txs, receipts)
if err != nil { return err }
if err := spec.Validate(); err != nil {
    return err
}
for addr, amount := range spec.Rewards {
    state.AddBalance(addr, amount)
}
``` [9](#0-8) 

Since the negative `MintingAmount` is a ratified governance parameter applied to every block, **no valid block can be finalized** after the vote takes effect — the chain halts permanently.

---

### Impact Explanation

A permanent chain halt is an invalid state transition affecting all honest nodes. No block can be finalized, withdrawals, transfers, and settlements all stop. This matches the allowed impact: *"Invalid state transition … or consensus divergence on honest nodes."*

---

### Likelihood Explanation

In `"none"` governance mode, any single GC member who becomes a block proposer can inscribe the malicious vote in `header.Vote`. The vote is ratified at the next epoch boundary (604,800 blocks on Mainnet, ~1 week). In `"single"` mode the governing node is required. Private chains and testnets using `"none"` mode are directly at risk; Mainnet requires the governing node to be compromised.

---

### Recommendation

Replace `noopFormatChecker` for `RewardMintingAmount` with a non-negative check, matching the pattern already used for `RewardMinimumStake`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok { return false }
        return v.Sign() >= 0
    },
    ...
},
``` [10](#0-9) 

---

### Proof of Concept

1. Deploy a chain with `governance.governancemode = "none"` (any GC member may vote).
2. As any GC member, call:
   ```
   governance_vote("reward.mintingamount", "-9600000000000000000")
   ```
3. Wait one epoch for the vote to be ratified into `header.Governance`.
4. From the next epoch, `GetParamSet(N).MintingAmount` returns `-9.6e18`.
5. Every call to `FinalizeState` for block `N` onwards computes negative per-address rewards (e.g., proposer reward = `-9.6e18 + execFee < 0`).
6. `spec.Validate()` returns `ErrNegativeRewardAmount`; `FinalizeState` propagates the error.
7. No block can be finalized — the chain halts permanently.

### Citations

**File:** kaiax/gov/param.go (L94-112)
```go
	bigIntCanonicalizer canonicalizerT = func(v any) (any, error) {
		switch v := v.(type) {
		case []byte:
			cv, ok := new(big.Int).SetString(string(v), 10)
			if !ok {
				return nil, ErrCanonicalizeByteToBigInt
			}
			return cv, nil
		case string:
			cv, ok := new(big.Int).SetString(v, 10)
			if !ok {
				return nil, ErrCanonicalizeStringToBigInt
			}
			return cv, nil
		case *big.Int:
			return v, nil
		}
		return nil, ErrCanonicalizeBigInt
	}
```

**File:** kaiax/gov/param.go (L160-162)
```go
func noopFormatChecker(cv any) bool {
	return true
}
```

**File:** kaiax/gov/param.go (L414-424)
```go
	RewardMintingAmount: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: noopFormatChecker,
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.Reward == nil || c.Governance.Reward.MintingAmount == nil {
				return nil, errors.New("reward is not set")
			}
			return c.Governance.Reward.MintingAmount, nil
		},
		DefaultValue: big.NewInt(0),
	},
```

**File:** kaiax/gov/param.go (L425-433)
```go
	RewardMinimumStake: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
		},
```

**File:** kaiax/gov/param.go (L561-572)
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

**File:** kaiax/reward/impl/getter.go (L224-265)
```go
// getDeferredRewardSimple is for Simple policy.
func getDeferredRewardSimple(config *reward.RewardConfig, execFee, blobFee *big.Int) (*reward.RewardSpec, error) {
	spec := reward.NewRewardSpec()
	minted := new(big.Int).Set(config.MintingAmount)

	// Non-deferred mode
	if !config.DeferredTxFee {
		var proposer *big.Int
		if config.Rules.IsMagma {
			// In non-deferred mode, no fees to distribute here at the end of block processing.
			// Just distribute the minting reward to the proposer and stop.
			proposer = new(big.Int).Set(minted)
			execFee = big.NewInt(0)
		} else {
			// But Simple policy had a bug where transaction fees were distributed to the proposer here at the end of block processing
			// despite configured to non-deferred mode. To keep the backward compatibility, the buggy behavior retains until Magma.
			proposer = new(big.Int).Add(minted, execFee)
		}
		spec.Minted = new(big.Int).Set(minted)
		// Both exec fees and blob fees are burned during state transition in non-deferred mode,
		// not at finalization. TotalFee/BurntFee are completed by specWithNonDeferredFee (GetBlockReward only).
		spec.TotalFee = execFee // Note that we've set it to 0 for non-deferred + Magma (see above).
		spec.BurntFee = big.NewInt(0)
		spec.Proposer = proposer
		spec.IncRecipient(config.Rewardbase, proposer)
		return spec, nil
	}

	// Deferred mode
	burntFee := big.NewInt(0)
	if config.Rules.IsMagma {
		burntFee = getBurnAmountMagma(execFee)
	}
	proposer := new(big.Int).Add(minted, execFee)
	proposer.Sub(proposer, burntFee)

	spec.Minted = minted
	spec.TotalFee = new(big.Int).Add(execFee, blobFee)
	spec.BurntFee = new(big.Int).Add(burntFee, blobFee)
	spec.Proposer = proposer
	spec.IncRecipient(config.Rewardbase, proposer)
	return spec, nil
```

**File:** kaiax/reward/impl/getter.go (L334-368)
```go
// getDeferredRewardFullKore is for non-Simple policy and after Kore.
func getDeferredRewardFullKore(config *reward.RewardConfig, execFee, burntFee, blobFee *big.Int, si *staking.StakingInfo) (*reward.RewardSpec, error) {
	var (
		spec             = reward.NewRewardSpec()
		minted           = new(big.Int).Set(config.MintingAmount)
		distributableFee = new(big.Int).Sub(execFee, burntFee)
	)

	// Distribute using RewardRatio first. Unlike Legacy, fees are not distributed here
	// because fees are exclusively allocated to proposer. By the way, remainder goes to KIF.
	validators, kif, kef := config.RewardRatio.Split(minted)
	proposer, stakers := config.Kip82Ratio.Split(validators)
	ratioRemainder := calcRemainder(minted, proposer, stakers, kif, kef)
	kif.Add(kif, ratioRemainder)

	// Further distribute using Kip82Ratio. By the way, remainder goes to proposer.
	// After Prague, if the CLStaking is not nil, the proposer and staking rewards are proportionally distributed to both CN and CL.
	// For proposer rewards, see `specWithProposerAndFunds`.
	stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
	proposer.Add(proposer, kip82Remainder)
	stakers.Sub(stakers, kip82Remainder)

	// Proposer gets the fees.
	proposer.Add(proposer, distributableFee)

	spec.Minted = minted
	spec.TotalFee = new(big.Int).Add(execFee, blobFee)
	spec.BurntFee = new(big.Int).Add(burntFee, blobFee)
	spec.Stakers = stakers
	for addr, amount := range stakersAlloc {
		spec.IncRecipient(addr, amount)
	}
	spec = specWithProposerAndFunds(spec, config, proposer, kif, kef, si)
	return spec, nil
}
```

**File:** kaiax/reward/spec.go (L118-125)
```go
func (spec *RewardSpec) Validate() error {
	for addr, amount := range spec.Rewards {
		if amount.Sign() < 0 {
			return errNegativeRewardAmount(addr, amount)
		}
	}
	return nil
}
```

**File:** kaiax/reward/impl/blockstate.go (L46-56)
```go
	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
```
