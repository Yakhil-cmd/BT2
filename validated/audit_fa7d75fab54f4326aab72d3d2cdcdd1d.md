### Title
`checkConsistency` Validates Current Governing Node Instead of Proposed New Governing Node, Allowing Governance Lock — (`kaiax/gov/headergov/impl/header.go`)

### Summary

In `checkConsistency`, the `GovernanceGoverningNode` vote case checks whether the **current** governing node (`params.GoverningNode`) is in the council, rather than whether the **proposed new** governing node (`vote.Value()`) is in the council. Because the current governing node is always in the council by the time this check is reached (enforced by earlier guards in `VerifyVote`), the check is a permanent no-op and always passes. This allows the governing node to ratify a vote that sets the governing node to any arbitrary address — including one that is not a council member — permanently locking governance in `single` mode.

### Finding Description

`VerifyVote` enforces two guards before calling `checkConsistency`:

1. The voter must be in the council (`!slices.Contains(council, vote.Voter())` → `ErrInvalidKeyValue`).
2. After the Permissionless fork in `single` mode, the voter must be the governing node (`vote.Voter() != params.GoverningNode` → `ErrVotePermissionDenied`).

So when `checkConsistency` is reached for a `GovernanceGoverningNode` vote in `single` mode, `params.GoverningNode` is guaranteed to equal `vote.Voter()`, who is guaranteed to be in the council. The consistency check then evaluates:

```go
if slices.Contains(council, params.GoverningNode) {
    return nil          // always taken
}
return ErrGovNodeNotInValSetList   // unreachable
```

The check should instead validate the **proposed** new governing node:

```go
if slices.Contains(council, vote.Value().(common.Address)) {
    return nil
}
return ErrGovNodeNotInValSetList
```

Because `params.GoverningNode` is used instead of `vote.Value().(common.Address)`, any address — including one that is not a validator — can be installed as the new governing node. [1](#0-0) [2](#0-1) 

### Impact Explanation

Once the governing node is changed to an address that is not in the council:

- `VerifyVote` rejects every subsequent vote from that address (line 88–90: voter must be in council).
- In `single` mode no other council member may vote (lines 103–107).
- No vote can ever be cast again, so the governance mode cannot be changed back to `none`.
- All mutable governance parameters (`unitprice`, `mintingamount`, `ratio`, `committeesize`, validator add/remove, etc.) are permanently frozen at their current values.
- The chain continues to produce blocks, but governance is irreversibly locked.

This satisfies the allowed-impact gate: **invalid state transition / persistent corruption of protected chain state** (governance parameter set) and **governance privilege escalation that changes protected chain state**. [3](#0-2) [4](#0-3) 

### Likelihood Explanation

The trigger requires only the governing node (a single semi-trusted key) to cast one `GovernanceGoverningNode` vote with a non-council target address. This can happen by:

- Operator error (typo in the target address).
- Key compromise of the governing node.
- Deliberate malicious action by the governing node.

No majority-validator collusion is required; a single valid block from the governing node is sufficient to ratify the vote at the next epoch boundary.

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
-   if slices.Contains(council, params.GoverningNode) {
+   if slices.Contains(council, vote.Value().(common.Address)) {
        return nil
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

### Proof of Concept

1. Chain is in `single` governance mode; `GoverningNode = A`; `A` is in the council.
2. `A` calls `governance_vote("governance.governingnode", "0xdeadbeef...dead")` where `0xdead...` is not a council member.
3. `A` proposes a block containing `header.Vote = encode(voter=A, name="governance.governingnode", value=0xdead...)`.
4. `VerifyVote` passes: voter `A` is in council ✓, `A` is the proposer ✓, `A` is the governing node ✓.
5. `checkConsistency` evaluates `slices.Contains(council, params.GoverningNode)` = `slices.Contains(council, A)` = **true** → returns `nil`. The vote is accepted.
6. At the next epoch block, `header.Governance` encodes `{"governance.governingnode": "0xdead..."}`. All nodes apply it.
7. From that epoch onward, `GoverningNode = 0xdead...`. `0xdead...` is not in the council, so `VerifyVote` rejects every vote it tries to cast. No other council member can vote in `single` mode. Governance is permanently locked. [5](#0-4)

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

**File:** kaiax/gov/headergov/impl/header.go (L159-178)
```go
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
