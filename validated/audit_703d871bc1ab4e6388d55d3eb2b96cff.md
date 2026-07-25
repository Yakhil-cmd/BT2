### Title
Missing Non-Negativity Validation on `reward.mintingamount` Governance Parameter Allows Negative Minting Amount — (File: `kaiax/gov/param.go`)

---

### Summary

The `reward.mintingamount` governance parameter is defined with `FormatChecker: noopFormatChecker`, which unconditionally accepts any canonicalized `*big.Int` value — including zero and negative values. In contrast, the structurally identical `RewardMinimumStake` and `RewardStakingRewardThreshold` parameters both enforce `v.Sign() >= 0`. A council member (in `none` governance mode) or the governing node (in `single` mode) can vote to set `reward.mintingamount` to a negative value. The vote passes all validation gates, is ratified at the next epoch boundary, and corrupts every subsequent block's reward distribution.

---

### Finding Description

In `kaiax/gov/param.go`, the `RewardMintingAmount` entry is:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: noopFormatChecker,   // ← always returns true
    ...
    DefaultValue: big.NewInt(0),
},
``` [1](#0-0) 

The `bigIntCanonicalizer` accepts negative decimal strings:

```go
case string:
    cv, ok := new(big.Int).SetString(v, 10)   // parses "-9600000000000000000" as negative
    if !ok {
        return nil, ErrCanonicalizeStringToBigInt
    }
    return cv, nil
``` [2](#0-1) 

`noopFormatChecker` never rejects any value:

```go
func noopFormatChecker(cv any) bool {
    return true
}
``` [3](#0-2) 

Compare with `RewardMinimumStake` and `RewardStakingRewardThreshold`, which both enforce non-negativity:

```go
FormatChecker: func(cv any) bool {
    v, ok := cv.(*big.Int)
    if !ok { return false }
    return v.Sign() >= 0
},
``` [4](#0-3) [5](#0-4) 

`NewVoteData` runs canonicalization then the format check; because `noopFormatChecker` always passes, a vote for `reward.mintingamount = "-9600000000000000000"` is accepted as valid:

```go
cv, err := param.Canonicalizer(value)
...
if !param.FormatChecker(cv) {
    ...
    return nil
}
return &voteData{...}
``` [6](#0-5) 

`VerifyVote` calls `checkConsistency`, which has no case for `RewardMintingAmount` and falls through to `return nil`:

```go
case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, ...,
    gov.RewardMintingAmount, ...:
    return nil
``` [7](#0-6) 

The ratified value is stored and later consumed by `NewRewardConfig`:

```go
rc.MintingAmount = new(big.Int).Set(paramset.MintingAmount)
``` [8](#0-7) 

A negative `MintingAmount` propagates into every block's `FinalizeState` reward calculation, causing the minting component of the reward to be subtracted from (rather than added to) the proposer's balance.

---

### Impact Explanation

Setting `reward.mintingamount` to a negative value corrupts the per-block reward distribution for every block after the epoch boundary at which the vote is ratified. The minting reward — normally credited to the proposer and stakers — becomes a deduction, effectively burning KAIA from the proposer's account each block. This is an unauthorized, persistent alteration of reward distribution affecting KAIA on every block until a corrective vote is ratified in a subsequent epoch.

---

### Likelihood Explanation

In `none` governance mode (the default), any single council member can cast the last vote in an epoch and have it ratified unilaterally. The `governance_vote` RPC is publicly accessible to any node whose address is in the council. The attack requires no special tooling — a single JSON-RPC call with a negative string value suffices. In `single` mode the governing node is required, raising the bar, but the missing guard is identical.

---

### Recommendation

Add a non-negativity `FormatChecker` to `RewardMintingAmount`, consistent with `RewardMinimumStake` and `RewardStakingRewardThreshold`:

```go
RewardMintingAmount: {
    Canonicalizer: bigIntCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(*big.Int)
        if !ok {
            return false
        }
        return v.Sign() >= 0   // reject negative minting amounts
    },
    ...
},
``` [1](#0-0) 

---

### Proof of Concept

1. A council member (in `none` mode) calls:
   ```
   governance_vote("reward.mintingamount", "-9600000000000000000")
   ```
2. `NewVoteData` runs `bigIntCanonicalizer("-9600000000000000000")` → `*big.Int(-9.6e18)`, then `noopFormatChecker` → `true`. Vote is stored.
3. The proposer node embeds the vote in `header.Vote`. `VerifyVote` → `checkConsistency` → falls through to `return nil`. All peers accept the block.
4. At the next epoch boundary, `getExpectedGovernance` ratifies the vote. The epoch block's `header.Governance` contains `{"reward.mintingamount": "-9600000000000000000"}`.
5. `GetParamSet` for all subsequent blocks returns `MintingAmount = -9.6e18`.
6. `NewRewardConfig` sets `rc.MintingAmount = -9.6e18`.
7. Every call to `FinalizeState` distributes a negative minting reward: the proposer's balance is decremented by the minting amount each block, burning KAIA from the proposer's account indefinitely until a corrective vote is ratified. [9](#0-8) [10](#0-9) [11](#0-10) [12](#0-11)

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

**File:** kaiax/gov/param.go (L427-432)
```go
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
```

**File:** kaiax/gov/param.go (L499-504)
```go
		FormatChecker: func(cv any) bool {
			v, ok := cv.(*big.Int)
			if !ok {
				return false
			}
			return v.Sign() >= 0
```

**File:** kaiax/gov/headergov/vote.go (L29-54)
```go
func NewVoteData(voter common.Address, name string, value any) VoteData {
	param, ok := gov.Params[gov.ParamName(name)]
	if !ok {
		param, ok = gov.ValidatorParams[gov.ParamName(name)]
		if !ok {
			logger.Error("Invalid vote name", "name", name)
			return nil
		}
	}

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

**File:** kaiax/gov/headergov/impl/header.go (L61-110)
```go
func (h *headerGovModule) VerifyVote(header *types.Header) error {
	if len(header.Vote) == 0 {
		return nil
	}

	var (
		vb       headergov.VoteBytes = header.Vote
		blockNum                     = header.Number.Uint64()
	)

	vote, err := vb.ToVoteData()
	if err != nil {
		logger.Error("ToVoteData error", "num", blockNum, "vote", vb, "err", err)
		return err
	}

	if gov.DeprecatedAt(vote.Name(), h.ChainConfig.Rules(header.Number)) {
		logger.Error("Vote is deprecated", "num", blockNum, "name", vote.Name())
		return ErrDeprecatedVote
	}

	council, err := h.ValSet.GetCouncil(blockNum)
	if err != nil {
		return err
	}

	// check if the voter is in council
	if !slices.Contains(council, vote.Voter()) {
		return ErrInvalidKeyValue
	}

	// check if Voter is the block proposer.
	author, err := h.Chain.Sealer().Author(header)
	if err != nil {
		return err
	}
	if author != vote.Voter() {
		return ErrInvalidVoter
	}

	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}

	return h.checkConsistency(blockNum, vote)
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
