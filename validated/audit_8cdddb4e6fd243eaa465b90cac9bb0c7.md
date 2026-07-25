### Title
Single Council Member Can Redirect All Flex-Rule Staking Rewards to Proposer via Unbounded `reward.stakingrewardthreshold` Vote in `none`-Mode Governance — (`kaiax/reward/impl/getter.go`, `kaiax/gov/param.go`)

### Summary

In `none`-mode header governance, any council member (a semi-trusted validator) can cast a vote to raise `reward.stakingrewardthreshold` to an arbitrarily large value. Once ratified, `assignStakingRewardsFlex` finds `totalExcessInt == 0` for every validator and silently returns the entire staking-reward budget as a remainder to the block proposer. Every block thereafter, the staking-reward portion of KAIA minting (e.g. 3.84e18 kei per block in a typical config) is paid to the proposer instead of being distributed to stakers.

### Finding Description

**Dispatch path (Osaka + `UseFlexReward`)**

`getDeferredRewardFull` routes to `getDeferredRewardFullFlex` when `config.Rules.IsOsaka && config.UseFlexReward`: [1](#0-0) 

Inside `getDeferredRewardFullFlex`, the staking-reward remainder is unconditionally added to the proposer: [2](#0-1) 

**The zero-excess path in `assignStakingRewardsFlex`**

The function computes `excessInt[cn.RewardAddr] = amount - threshold` only when `amount > threshold`. If no validator satisfies this condition, `totalExcessInt` stays `0`, the inner loop is skipped entirely, and `remaining` (which equals the full `budget`) is returned as the remainder: [3](#0-2) [4](#0-3) 

The test case `"flex, all below threshold, no staking reward"` (threshold = 9 000 000 KAIA, all validators ≈ 5 000 000 KAIA) confirms the proposer receives `3.84e18 + 3.5e16` kei — the full staking budget — while `Stakers = 0`: [5](#0-4) 

**No upper-bound guard on the parameter**

The `FormatChecker` for `RewardStakingRewardThreshold` only rejects negative values: [6](#0-5) 

`checkConsistency` returns `nil` for this parameter with no additional validation: [7](#0-6) 

**`none`-mode governance allows any council member to cast the decisive vote**

In `none` mode, all council members may vote; the last vote in an epoch is ratified: [8](#0-7) 

The `Vote` API enforces the `single`-mode restriction but imposes no restriction in `none` mode: [9](#0-8) 

`VerifyVote` likewise only blocks non-governing-node voters in `single` mode after the Permissionless fork: [10](#0-9) 

### Impact Explanation

Every block produced under the Osaka + `UseFlexReward` rules after the malicious governance ratification, the staking-reward portion of the minting amount (e.g. `gsM` kei, where `g` = validator ratio, `s` = staker KIP-82 ratio, `M` = minting amount) is transferred to the block proposer's reward address instead of being distributed proportionally to stakers. This is an unauthorized redistribution of KAIA from stakers to the proposer, matching the allowed impact category "unauthorized reward distribution affecting KAIA."

### Likelihood Explanation

- **Trigger**: A single council member in a `none`-mode chain. `none` mode is a valid, documented production configuration (used in tests and available to any chain that does not set `single` at genesis).
- **Effort**: The attacker must be the last voter for `reward.stakingrewardthreshold` in an epoch. Because proposers rotate, the attacker simply waits until they are scheduled to propose a block near the epoch boundary and submits the vote then.
- **Cost**: No capital beyond the minimum staking requirement to be a council member.
- **Persistence**: The effect persists until another council member successfully overrides the vote in a subsequent epoch.

### Recommendation

1. **Add an upper-bound `FormatChecker`** for `RewardStakingRewardThreshold` in `kaiax/gov/param.go` — e.g., reject values that exceed `reward.minimumstake` by more than a configurable multiplier, or cap it at the current maximum observed staking amount.
2. **Add a `checkConsistency` guard** in `kaiax/gov/headergov/impl/header.go` that rejects a `reward.stakingrewardthreshold` vote whose value would render all current validators ineligible for staking rewards.
3. **Fallback in `assignStakingRewardsFlex`**: when `totalExcessInt == 0`, distribute the budget equally among all `minStake`-eligible validators rather than returning it as a proposer remainder, mirroring the documented Kore-rule fallback.

### Proof of Concept

```
Chain config: none-mode governance, Osaka hardfork, UseFlexReward=true
Validators: V1..V4, each staking 5 000 001 KAIA (just above minStake = 5 000 000)
Default StakingRewardThreshold: 5 000 000 KAIA

Step 1 – Attacker (V1, a council member) waits until near the end of epoch k.
Step 2 – When V1 is scheduled as proposer, it casts:
         governance_vote("reward.stakingrewardthreshold", "999999999999999999")
         (any value > 5 000 001 KAIA suffices)
Step 3 – At epoch block k*epoch, the vote is ratified and written to header.Governance.
Step 4 – From block (k+1)*epoch onward, assignStakingRewardsFlex computes:
           amount = 5 000 001 < threshold = 999 999 999 999 999 999
           → excessInt is empty, totalExcessInt = 0
           → remaining = budget (full staking reward, e.g. 3.84e18 kei/block)
           → kip82Remainder = 3.84e18 kei returned to proposer
Step 5 – Every block, the proposer receives the full staking budget.
         Stakers receive 0 KAIA staking rewards.
         V1 earns disproportionate KAIA whenever it proposes.
```

The corrupted value is `spec.Stakers` (set to `0` instead of `gsM`) and `spec.Proposer` (inflated by `gsM` kei per block), persisted into the state via `FinalizeState` for every block in the affected epoch. [11](#0-10) [12](#0-11) [6](#0-5) [13](#0-12)

### Citations

**File:** kaiax/reward/impl/getter.go (L289-291)
```go
	if config.Rules.IsOsaka && config.UseFlexReward {
		return getDeferredRewardFullFlex(config, execFee, burntFee, blobFee, si)
	} else if config.Rules.IsKore {
```

**File:** kaiax/reward/impl/getter.go (L299-331)
```go
// getDeferredRewardFullFlex is for non-Simple policy, after Kore, and with UseFlexReward enabled.
func getDeferredRewardFullFlex(config *reward.RewardConfig, execFee, burntFee, blobFee *big.Int, si *staking.StakingInfo) (*reward.RewardSpec, error) {
	var (
		spec             = reward.NewRewardSpec()
		minted           = new(big.Int).Set(config.MintingAmount)
		distributableFee = new(big.Int).Sub(execFee, burntFee)
	)

	// Distribute using RewardRatio (4-part) first. Unlike Legacy, fees are not distributed here
	// because fees are exclusively allocated to proposer. By the way, remainder goes to KIF.
	validators, kif, kef, kpf := config.RewardRatio.SplitFlex(minted)
	proposer, stakers := config.Kip82Ratio.Split(validators)
	ratioRemainder := calcRemainder(minted, proposer, stakers, kif, kef, kpf)
	kif.Add(kif, ratioRemainder)

	// Further distribute using Kip82Ratio. By the way, remainder goes to proposer.
	stakersAlloc, kip82Remainder := assignStakingRewardsFlex(config, stakers, si)
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

	spec = specWithProposerAndFundsFlex(spec, config, proposer, kif, kef, kpf, si)
	return spec, nil
```

**File:** kaiax/reward/impl/getter.go (L421-483)
```go
// assignStakingRewardsFlex assigns staking rewards to stakers according to their staking amounts.
// Returns the allocation and the remainder.
func assignStakingRewardsFlex(config *reward.RewardConfig, budget *big.Int, si *staking.StakingInfo) (map[common.Address]*big.Int, *big.Int) {
	var (
		minStake  = config.MinimumStake.Uint64()
		threshold = config.StakingRewardThreshold.Uint64()
		isPrague  = config.Rules.IsPrague

		cns            = si.ConsolidatedNodes()
		excessInt      = make(map[common.Address]uint64)
		totalExcessInt = uint64(0)
	)

	// Calculate the excess stakes (the amount over the threshold) for each CN.
	for _, cn := range cns {
		// If the CNStaking is less than minStake, skip it. Even if (CNStaking + CLStaking) could be more than minStake,
		// the CNStaking alone must be at least minStake to be eligible.
		if cn.StakingAmount < minStake {
			continue
		}

		amount := cn.StakingAmount
		if isPrague && cn.CLStakingInfo != nil {
			amount += cn.CLStakingInfo.CLStakingAmount
		}

		// Excess is the amount over the threshold (not over minStake).
		if amount > threshold {
			excessInt[cn.RewardAddr] = amount - threshold
			totalExcessInt += excessInt[cn.RewardAddr]
		}
	}

	// Distribute the budget to the CNs based on the excess stakes.
	var (
		totalExcess = new(big.Int).SetUint64(totalExcessInt)
		remaining   = new(big.Int).Set(budget)
		alloc       = make(map[common.Address]*big.Int)
	)
	for _, cn := range cns {
		if excessInt[cn.RewardAddr] <= 0 {
			continue
		}
		excess := new(big.Int).SetUint64(excessInt[cn.RewardAddr])

		// The KAIA unit will cancel out:
		// reward (kei) = excess (KAIA) * budget (kei) / totalExcess (KAIA)
		reward := new(big.Int).Div(new(big.Int).Mul(excess, budget), totalExcess)
		if reward.Sign() <= 0 {
			continue
		}

		// If Prague and CL is configured for this CN, split the reward between CN and CL.
		if isPrague && cn.CLStakingInfo != nil {
			cnAmount, clAmount := cn.Split(reward)
			alloc[cn.RewardAddr] = cnAmount
			alloc[cn.CLStakingInfo.CLPoolAddr] = clAmount
		} else {
			alloc[cn.RewardAddr] = reward
		}
		remaining.Sub(remaining, reward)
	}
	return alloc, remaining
```

**File:** kaiax/reward/impl/getter_test.go (L1082-1100)
```go
		{"flex, all below threshold, no staking reward", true, big.NewInt(9_000_000), kpfAddr, &reward.RewardSpec{
			RewardSummary: reward.RewardSummary{
				Minted:   mintingAmount,
				TotalFee: big.NewInt(7e16),
				BurntFee: big.NewInt(3.5e16), // F/2
			},
			Proposer: big.NewInt(3.84e18 + 3.5e16), // fee/2 + stakers
			Stakers:  big.NewInt(0),                // no stakers were eligible
			KIF:      big.NewInt(2.40e18),
			KEF:      big.NewInt(2.40e18),
			KPF:      big.NewInt(0.96e18),
			Rewards: map[common.Address]*big.Int{
				// Proposer and funds
				common.HexToAddress("0xfff"): big.NewInt(3.84e18 + 3.5e16),
				common.HexToAddress("0xd01"): big.NewInt(2.40e18),
				common.HexToAddress("0xd02"): big.NewInt(2.40e18),
				common.HexToAddress("0xd03"): big.NewInt(0.96e18),
			},
		}},
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

**File:** kaiax/gov/headergov/impl/header.go (L101-107)
```go
	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/header.go (L156-215)
```go
// checkConsistency checks if vote values are consistent with chain states such as other parameters and validator set.
func (h *headerGovModule) checkConsistency(blockNum uint64, vote headergov.VoteData) error {
	switch vote.Name() {
	case gov.GovernanceGoverningNode:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}

		// we'll use blockNum-1 for the blocknumber of GetCouncil since blockNum cannot be available(eg. vote)
		// it's definite that the valSet vote is not included in this block
		// so the council(blockNum - 1) and council(blockNum) should be same
		council, err := h.ValSet.GetCouncil(blockNum - 1)
		if err != nil {
			return err
		}

		if slices.Contains(council, params.GoverningNode) {
			return nil
		}
		return ErrGovNodeNotInValSetList
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
	case gov.AddValidator, gov.RemoveValidator:
		params := h.GetParamSet(blockNum)

		// compare with governing node only in single mode.
		if params.GovernanceMode != "single" {
			return nil
		}
		if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
			return ErrGovNodeInValSetVoteValue
		}
		return nil
		// These votes are valid as long as it passes the format checks in NewVoteData(). No more checks here.
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
	default:
		return ErrInvalidKeyValue
	}
}
```

**File:** kaiax/gov/headergov/README.md (L44-47)
```markdown
The ratification condition is determined by the `governance.governancemode` parameter. Mainnet and Kairos both operate in `single` mode. There are two governance modes:

- `none` mode: all members of the GC can vote. For each governance parameter, the last vote in the epoch will be ratified.
- `single` mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified in block order. For each governance parameter, the last vote in the epoch will be ratified.
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
