Now I have all the information needed. The bug is confirmed. Let me write the report.

---

### Title
Wrong Address Validated in `checkConsistency` for `GovernanceGoverningNode` Vote — Allows Setting Non-Council Address as Governing Node, Permanently Locking Governance - (File: `kaiax/gov/headergov/impl/header.go`)

### Summary

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` validates the **current** `params.GoverningNode` against the council instead of the **proposed new** governing node (`vote.Value()`). This is the direct Kaia analog of the external bug: checking the wrong address in a privileged-state-change validation. Any council member (before the Permissionless fork) can cast a `governance.governingnode` vote pointing to an arbitrary non-council address; the check passes because the current governing node is already in the council. Once ratified, the chain's governing node is permanently set to an address that can never propose blocks, irreversibly locking all header-governance parameter changes.

### Finding Description

In `checkConsistency` (`kaiax/gov/headergov/impl/header.go`, lines 159–178):

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
    if slices.Contains(council, params.GoverningNode) { // BUG: checks current node, not vote.Value()
        return nil
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

The intent of this check (as indicated by `ErrGovNodeNotInValSetList`) is to ensure the **new** governing node being voted for is a member of the council. The vote value for `GovernanceGoverningNode` is a `common.Address` (confirmed by `param.go`): [2](#0-1) 

But the code checks `params.GoverningNode` — the **current** governing node — not `vote.Value().(common.Address)` — the **proposed** new governing node. Since the current governing node is almost always in the council, the check trivially passes for any proposed value, including addresses that are not council members.

`checkConsistency` is called from both `VerifyVote` (consensus path, called on every block import) and the `Vote` API: [3](#0-2) [4](#0-3) 

Before the Permissionless fork, `VerifyVote` does **not** restrict votes to the governing node — any council member who becomes a proposer can embed a `governance.governingnode` vote in a block header: [5](#0-4) 

This is confirmed by the test: [6](#0-5) 

### Impact Explanation

Once a `governance.governingnode` vote for a non-council address is ratified at an epoch block, `params.GoverningNode` is permanently set to that address. In `"single"` governance mode (used by Kaia Mainnet and Kairos testnet), only the governing node can vote. Because the new governing node is not in the council, it can never be selected as a proposer, and therefore can never embed a vote in a block header. All future governance parameter changes — reward ratios, minting amounts, committee sizes, base fees, and all other `kaiax/gov` parameters — become permanently impossible. This is an irreversible corruption of protected governance state.

### Likelihood Explanation

**Before Permissionless fork**: Any council member who becomes a block proposer can trigger this. Council members are semi-trusted validators, but a single malicious or compromised council member is sufficient. No coordination is required.

**After Permissionless fork**: Only the governing node can vote, making this a privileged-actor path.

Kaia Mainnet and Kairos testnet operate in `"single"` mode. The Permissionless fork activation is chain-config-dependent. On chains where it is not yet active, the attack surface is any council member.

### Recommendation

Replace the check in `checkConsistency` for `gov.GovernanceGoverningNode` to validate the **proposed** new governing node (the vote value) against the council, not the current governing node:

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
    // FIX: check the proposed new governing node, not the current one
    newGovNode := vote.Value().(common.Address)
    if slices.Contains(council, newGovNode) {
        return nil
    }
    return ErrGovNodeNotInValSetList
```

### Proof of Concept

1. Chain is in `"single"` governance mode, Permissionless fork not yet active.
2. Attacker is a council member (validator). They call `governance_vote("governance.governingnode", "0x000000000000000000000000000000000000dead")` where `0x...dead` is not in the council.
3. `Vote` API calls `checkConsistency(nextBlock, vote)`. The check evaluates `slices.Contains(council, params.GoverningNode)` — the **current** governing node is in the council, so the check returns `nil` (passes).
4. The vote is queued. When the attacker's node becomes a proposer, the vote is embedded in `header.Vote`.
5. `VerifyVote` is called by all nodes during block import. `checkConsistency` again checks the current governing node (in council) — passes. Block is accepted.
6. At the next epoch block, the vote is ratified. `params.GoverningNode` is now `0x...dead`.
7. In `"single"` mode, only `0x...dead` can vote. `0x...dead` is not in the council, so it is never a proposer, so it can never embed a vote. All governance parameter changes are permanently blocked. [7](#0-6)

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

**File:** kaiax/gov/headergov/impl/api.go (L53-83)
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
}
```

**File:** kaiax/gov/headergov/impl/header_test.go (L126-134)
```go
	t.Run("pre-permissionless allows non-governing node", func(t *testing.T) {
		config.PermissionlessCompatibleBlock = nil
		h := newHeaderGovModule(t, config)
		vote := headergov.NewVoteData(validVoter, string(gov.GovernanceUnitPrice), uint64(100))
		vb, err := vote.ToVoteBytes()
		require.NoError(t, err)
		err = h.VerifyVote(&types.Header{Number: big.NewInt(1), Vote: vb, Extra: extra})
		assert.NoError(t, err)
	})
```
