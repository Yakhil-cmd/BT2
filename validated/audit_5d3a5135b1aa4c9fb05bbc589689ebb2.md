### Title
`governance.governingnode` Vote Accepts Non-Council New Owner, Permanently Locking Single-Mode Governance — (`File: kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` for a `governance.governingnode` vote validates that the **current** governing node is in the council, but never validates that the **proposed new** governing node is in the council. After ratification, the new governing node — which is not a validator and can never be a block proposer — can never inscribe votes in block headers. In `single` mode, only the governing node may vote, so governance is permanently frozen.

---

### Finding Description

In `kaiax/gov/headergov/impl/header.go`, `checkConsistency` handles a `governance.governingnode` vote as follows:

```go
case gov.GovernanceGoverningNode:
    params := h.GetParamSet(blockNum)
    if params.GovernanceMode != "single" {
        return nil
    }
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    ...
    if slices.Contains(council, params.GoverningNode) {  // checks CURRENT node
        return nil
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

The guard checks `params.GoverningNode` — the **current** governing node — against the council. It never checks `vote.Value().(common.Address)` — the **proposed new** governing node — against the council.

The `FormatChecker` for `GovernanceGoverningNode` only validates that the value is a valid `common.Address`; it imposes no council-membership requirement: [2](#0-1) 

After the vote is ratified at an epoch boundary, `GetParamSet` returns the new address as `GoverningNode`. In `VerifyVote`, post-Permissionless single mode enforces:

```go
if h.ChainConfig.IsPermissionlessForkEnabled(...) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [3](#0-2) 

Because the new governing node is not in the council, it can never be elected as a block proposer, and therefore can never inscribe a vote in `header.Vote`. No governance parameter can ever be changed again.

The same gap exists in the `Vote` API path, which also calls `checkConsistency`: [4](#0-3) 

---

### Impact Explanation

Once the ratified `governance.governingnode` points to a non-council address, the following governance parameters are permanently frozen in single mode:

- `reward.mintingamount` — minting/inflation rate
- `reward.ratio` / `reward.kip82ratio` — reward distribution splits
- `governance.unitprice` — base transaction fee
- `istanbul.committeesize` — committee size
- `governance.govparamcontract` — contract governance address
- All other mutable parameters listed in `kaiax/gov/README.md` [5](#0-4) 

This is a permanent, irreversible corruption of the governance state. The governing node's exclusive vote privilege (enforced at `VerifyVote`) becomes unexercisable, and no other node may vote in single mode.

---

### Likelihood Explanation

The trigger requires the current governing node (a semi-trusted privileged actor) to cast a `governance.governingnode` vote for an address not yet in the council — for example, intending to first transfer governance authority and then add the new node via `AddValidator`, without realising the order matters. The system provides no guard against this ordering mistake. On Kaia Mainnet and Kairos, `governance.governancemode` is `single`, making this path live.

---

### Recommendation

In `checkConsistency`, add a council-membership check for the **vote value** (the proposed new governing node), mirroring the existing check for the current governing node:

```go
case gov.GovernanceGoverningNode:
    params := h.GetParamSet(blockNum)
    if params.GovernanceMode != "single" {
        return nil
    }
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    if err != nil {
        return err
    }
    // Existing: current governing node must be in council
    if !slices.Contains(council, params.GoverningNode) {
        return ErrGovNodeNotInValSetList
    }
    // New: proposed new governing node must also be in council
    newGovNode, ok := vote.Value().(common.Address)
    if !ok || !slices.Contains(council, newGovNode) {
        return ErrNewGovNodeNotInValSetList
    }
    return nil
``` [6](#0-5) 

---

### Proof of Concept

**Setup:** Single-mode chain (Mainnet/Kairos configuration). Current governing node `A` is in the council. Address `X` is not in the council.

1. `A` calls `governance_vote("governance.governingnode", X)`.
2. `checkConsistency` runs: `params.GoverningNode == A`, `council` contains `A` → check passes, vote is queued.
3. At the next epoch boundary, the proposer writes `header.Governance = {"governance.governingnode": X}`.
4. `VerifyGov` accepts it (it matches the expected governance derived from the epoch's votes).
5. `GetParamSet(epochStart + 1)` now returns `GoverningNode = X`.
6. Any node attempts to cast a governance vote. `VerifyVote` checks `vote.Voter() != X` → `ErrVotePermissionDenied` for every council member.
7. `X` is not in the council, so it is never elected proposer, and can never write `header.Vote`.
8. Governance is permanently frozen; `reward.mintingamount`, `reward.ratio`, `governance.unitprice`, and all other mutable parameters can never be changed. [7](#0-6) [8](#0-7)

### Citations

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

**File:** kaiax/gov/param.go (L231-244)
```go
	GovernanceGoverningNode: {
		Canonicalizer: addressCanonicalizer,
		FormatChecker: func(cv any) bool {
			_, ok := cv.(common.Address)
			return ok
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil {
				return nil, errors.New("governance is not set")
			}
			return c.Governance.GoverningNode, nil
		},
		DefaultValue: common.HexToAddress("0x0000000000000000000000000000000000000000"),
	},
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

**File:** kaiax/gov/README.md (L17-44)
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

<immutable parameters - Mainnet configuration>
governance.governancemode: single
istanbul.epoch: 604800
istanbul.policy: 2
reward.deferredtxfee: true
reward.minimumstake: 5000000 (KAIA)
reward.proposerupdateinterval: 3600
reward.stakingupdateinterval: 86400
reward.useginicoeff: true
```
```
