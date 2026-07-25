### Title
Missing Non-Negativity Validation on `reward.mintingamount` Governance Parameter Enables Chain Halt via Negative Minting Amount — (File: `kaiax/gov/param.go`)

---

### Summary

The `RewardMintingAmount` governance parameter uses `noopFormatChecker` (accepts any value), while the structurally identical `RewardMinimumStake` and `RewardStakingRewardThreshold` parameters correctly enforce `v.Sign() >= 0`. A governance vote setting `reward.mintingamount` to a negative `*big.Int` passes every validation layer — `NewVoteData`, `VerifyVote`, and `checkConsistency` — and, once ratified, causes `FinalizeState` to return `ErrNegativeRewardAmount` on every subsequent block, permanently halting the chain.

---

### Finding Description

In `kaiax/gov/param.go`, the three `*big.Int`-typed reward parameters are defined as follows:

```
RewardMintingAmount      → Canonicalizer: bigIntCanonicalizer, FormatChecker: noopFormatChecker   ← NO sign check
RewardMinimumStake       → Canonicalizer: bigIntCanonicalizer, FormatChecker: v.Sign() >= 0       ← guarded
RewardStakingRewardThreshold → Canonicalizer: bigIntCanonicalizer, FormatChecker: v.Sign() >= 0   ← guarded
``` [1](#0-0) [2](#0-1) [3](#0-2) 

The `bigIntCanonicalizer` accepts negative string inputs (e.g., `"-9600000000000000000"`). Because `RewardMinimumStake` and `RewardStakingRewardThreshold` explicitly guard against negative values while `RewardMintingAmount` does not, a negative minting amount passes `NewVoteData` (returns non-nil), passes `VerifyVote` (format check is noop), and passes `checkConsistency` (the switch arm for `RewardMintingAmount` returns `nil` unconditionally): [4](#0-3) 

Once ratified at the next epoch boundary, `NewRewardConfig` copies the negative value into `rc.MintingAmount` without error: [5](#0-4) 

Every subsequent call to `getDeferredRewardFull` (or `getDeferredRewardFullKore`, `getDeferredRewardFullFlex`) sets `minted = new(big.Int).Set(config.MintingAmount)` to a negative number, propagates it through `RewardRatio.Split` and `Kip82Ratio.Split`, and writes negative amounts into `spec.Rewards`: [6](#0-5) 

`FinalizeState` then calls `spec.Validate()`, which detects the negative recipient balance and returns `ErrNegativeRewardAmount`: [7](#0-6) [8](#0-7) 

This error propagates out of `FinalizeState` for every block from the epoch the parameter takes effect, causing a permanent chain halt on all honest nodes.

---

### Impact Explanation

**Impact**: Invalid state transition / chain halt.

Once the negative `reward.mintingamount` is ratified and takes effect, `FinalizeState` fails with `ErrNegativeRewardAmount` on every block. No further blocks can be finalized. The corrupted governance parameter is stored in the persistent `govHistory` and applied to every subsequent `GetParamSet` call, making the halt permanent until a hard-fork or manual chain intervention.

The exact corrupted value is `MintingAmount < 0` in the `RewardConfig` struct, which propagates to negative entries in `spec.Rewards`, violating the invariant enforced by `spec.Validate()`.

---

### Likelihood Explanation

**Likelihood**: Low-to-medium.

In `single` governance mode (Mainnet/Kairos), only the governing node can cast votes. A typo — entering `"-9600000000000000000"` instead of `"9600000000000000000"` — is the minimal error required. In `none` mode, any council member can trigger this. The inconsistency with `RewardMinimumStake` (which is guarded) makes this a latent human-error trap rather than a theoretical concern.

---

### Recommendation

Add a non-negativity `FormatChecker` to `RewardMintingAmount`, consistent with the existing guards on `RewardMinimumStake` and `RewardStakingRewardThreshold`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok {
            return false
        }
        return v.Sign() >= 0   // add this guard
    },
    ...
},
``` [1](#0-0) 

---

### Proof of Concept

1. Governing node calls `governance_vote("reward.mintingamount", "-9600000000000000000")` via the `governance_vote` JSON-RPC API.
2. `headergov/impl/api.go` calls `headergov.NewVoteData(voter, name, value)`. The `bigIntCanonicalizer` converts the string to `big.NewInt(-9.6e18)`. `noopFormatChecker` returns `true`. `NewVoteData` returns a non-nil vote.
3. The vote is stored in `myVotes` and written to `header.Vote` when the governing node proposes a block.
4. `VerifyVote` on importing nodes: `ToVoteData` succeeds; `checkConsistency` for `RewardMintingAmount` returns `nil` (no check). Block is accepted.
5. At the next epoch block, the vote is ratified and written to `header.Governance`. `GetParamSet` now returns `MintingAmount = -9.6e18` for all subsequent blocks.
6. `NewRewardConfig` sets `rc.MintingAmount = big.NewInt(-9.6e18)` without error.
7. `getDeferredRewardFullKore` computes `minted = big.NewInt(-9.6e18)`, splits it into negative `validators`, `kif`, `kef`, `proposer`, `stakers`, and writes them into `spec.Rewards`.
8. `spec.Validate()` returns `ErrNegativeRewardAmount`.
9. `FinalizeState` returns the error. Block processing fails on all nodes. Chain halts permanently. [1](#0-0) [4](#0-3) [9](#0-8) [10](#0-9) [7](#0-6)

### Citations

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

**File:** kaiax/gov/param.go (L425-441)
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
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil || c.Governance.Reward == nil || c.Governance.Reward.MinimumStake == nil {
				return nil, errors.New("reward is not set")
			}
			return c.Governance.Reward.MinimumStake, nil
		},
		DefaultValue: big.NewInt(2000000),
	},
```

**File:** kaiax/gov/param.go (L497-515)
```go
	RewardStakingRewardThreshold: {
		Canonicalizer: bigIntCanonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			// This parameter may be absent in ChainConfig because it was introduced at Osaka.
			// However, ChainConfig.SetDefaults() should have set it to the default value.
			if c.Governance == nil || c.Governance.Reward == nil || c.Governance.Reward.StakingRewardThreshold == nil {
				return nil, errors.New("reward is not set")
			}
			return c.Governance.Reward.StakingRewardThreshold, nil
		},
		DefaultValue: big.NewInt(5_000_000),
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

**File:** kaiax/reward/config.go (L53-81)
```go
func NewRewardConfig(chainConfig *params.ChainConfig, govModule GovModule, header *types.Header) (*RewardConfig, error) {
	rc := &RewardConfig{}

	rc.Rules = chainConfig.Rules(header.Number)
	rc.Rewardbase = header.Rewardbase

	paramset := govModule.GetParamSet(header.Number.Uint64())
	rc.IsSimple = paramset.ProposerPolicy != uint64(istanbul.WeightedRandom)
	rc.UnitPrice = new(big.Int).SetUint64(paramset.UnitPrice)
	rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
	rc.MinimumStake = new(big.Int).Set(paramset.MinimumStake)
	rc.DeferredTxFee = paramset.DeferredTxFee
	rc.StakingRewardThreshold = new(big.Int).Set(paramset.StakingRewardThreshold)
	rc.UseFlexReward = paramset.UseFlexReward

	if ratio, err := NewRewardRatio(paramset.Ratio); err != nil {
		return nil, err
	} else {
		rc.RewardRatio = ratio
	}

	if kip82Ratio, err := NewRewardKip82Ratio(paramset.Kip82Ratio); err != nil {
		return nil, err
	} else {
		rc.Kip82Ratio = kip82Ratio
	}

	return rc, nil
}
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

**File:** kaiax/reward/impl/blockstate.go (L30-57)
```go
func (r *RewardModule) FinalizeState(header *types.Header, state *state.StateDB, txs []*types.Transaction, receipts []*types.Receipt) error {
	if r.GovModule.GetParamSet(header.Number.Uint64()).ProposerPolicy == uint64(istanbul.WeightedRandom) && common.EmptyHash(header.Root) {
		qualified, err := r.ValsetModule.GetQualifiedValidators(header.Number.Uint64())
		if err != nil {
			return err
		}
		useRewardAddress := valset.NewAddressSet(qualified).Contains(r.NodeAddress)

		if rewardAddr := r.GetRewardAddress(header.Number.Uint64(), r.NodeAddress); useRewardAddress && rewardAddr != (common.Address{}) {
			header.Rewardbase = rewardAddr
			logger.Trace("Use reward address for nodeValidator", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		} else {
			logger.Trace("No reward address for nodeValidator. Use node's rewardbase.", "header.Number", header.Number.Uint64(), "nodeAddress", r.NodeAddress, "rewardbase", header.Rewardbase)
		}
	}

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
}
```
