### Title
Wrong Variable in Governing-Node Vote Consistency Check Allows Setting Governing Node to Non-Council Address — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` validates a `governance.governingnode` vote by checking whether the **current** governing node is in the council, instead of checking whether the **proposed new** governing node (the vote value) is in the council. Because the current governing node is always in the council under normal operation, the check trivially passes for every vote, completely bypassing the intended guard. This allows the governing node to be changed to any arbitrary address — including one that is not a validator — permanently freezing governance.

### Finding Description

`checkConsistency` is called from `VerifyVote` during block-header verification. Its stated purpose is to ensure that vote values are consistent with current chain state. For the `GovernanceGoverningNode` case the code is:

```go
// kaiax/gov/headergov/impl/header.go  lines 159-178
case gov.GovernanceGoverningNode:
    params := h.GetParamSet(blockNum)
    if params.GovernanceMode != "single" {
        return nil
    }
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    if err != nil {
        return err
    }
    if slices.Contains(council, params.GoverningNode) {   // ← BUG: checks current node
        return nil
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

The intended invariant is: **the new governing node must already be a council member**. The correct check is `slices.Contains(council, vote.Value().(common.Address))`. Instead, the code checks `params.GoverningNode` — the **current** governing node — which is always in the council (otherwise governance would already be broken). The check therefore always returns `nil` (no error), regardless of what address the vote proposes.

Compare with the `AddValidator`/`RemoveValidator` case in the same function, which correctly uses `vote.Value()`:

```go
// kaiax/gov/headergov/impl/header.go  lines 193-203
case gov.AddValidator, gov.RemoveValidator:
    ...
    if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
        return ErrGovNodeInValSetVoteValue
    }
``` [2](#0-1) 

The `GovernanceGoverningNode` parameter is canonicalized to `common.Address` by `addressCanonicalizer`, so `vote.Value().(common.Address)` is the correct type assertion. [3](#0-2) 

### Impact Explanation

After a `governance.governingnode` vote is ratified at an epoch block, `GetParamSet` returns the new address as the governing node for all subsequent blocks. [4](#0-3) 

If the new address is not in the council:

1. It cannot be selected as a block proposer (proposers are drawn from `QualifiedValidators`, a subset of the council).
2. It therefore can never write `header.Vote`, so no further governance votes can be cast.
3. In single mode, no other council member is permitted to vote after the Permissionless fork (`ErrVotePermissionDenied`). [5](#0-4) 

The result is **permanent governance freeze**: no governance parameter — including `governance.governingnode` itself — can ever be changed again. This is a protected-state impact: the governance authority over all mutable chain parameters (fee bounds, reward ratios, minting amount, validator set, etc.) is irrecoverably transferred to an address that cannot exercise it.

Additionally, in single mode the governing node is unconditionally kept in `QualifiedValidators` to ensure it can always propose blocks: [6](#0-5) 

If the governing node is set to a non-council address, this protection is also lost, potentially affecting proposer selection.

### Likelihood Explanation

Before the Permissionless hardfork, any council member can cast a `governance.governingnode` vote in single mode (the `ErrVotePermissionDenied` guard is only active post-Permissionless). After Permissionless, only the current governing node can vote. In both cases the buggy check passes unconditionally whenever the current governing node is in the council, which is the normal state. The trigger is any valid `governance.governingnode` vote whose value is not a current council member — whether from operator error or a compromised governing key.

### Recommendation

Replace `params.GoverningNode` with `vote.Value().(common.Address)` in the `GovernanceGoverningNode` case of `checkConsistency`:

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
    // Check the PROPOSED new governing node, not the current one.
    if slices.Contains(council, vote.Value().(common.Address)) {
        return nil
    }
    return ErrGovNodeNotInValSetList
```

### Proof of Concept

1. Chain is in single governance mode; governing node is `GN` (a council member).
2. `GN` becomes block proposer and casts a `governance.governingnode` vote with value `X`, where `X` is **not** in the council.
3. `VerifyVote` calls `checkConsistency`. The `GovernanceGoverningNode` branch executes `slices.Contains(council, params.GoverningNode)` — i.e., `slices.Contains(council, GN)` — which returns `true` because `GN` is in the council. The vote is accepted.
4. At the next epoch block the vote is ratified; `GetParamSet` now returns `X` as the governing node.
5. `X` is not in the council, so it is never selected as proposer and can never write `header.Vote`.
6. No further governance votes can be cast. All mutable governance parameters are permanently frozen. [4](#0-3) [7](#0-6)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L57-110)
```go
// VerifyVote checks the following:
// (1) voter must be in valset,
// (2) integrity of the voter (the voter must be the block proposer),
// (3) the vote value must be consistent compared to the latest ParamSet.
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

**File:** kaiax/gov/headergov/impl/header.go (L156-178)
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
```

**File:** kaiax/gov/headergov/impl/header.go (L193-203)
```go
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

**File:** kaiax/valset/impl/getter_demote.go (L99-102)
```go
	// Under single governance mode, governing node cannot be demoted.
	if singleMode && demoted.Contains(governingNode) {
		demoted.Remove(governingNode)
	}
```
