### Title
`checkConsistency` Validates Current Governing Node Instead of Proposed New Governing Node, Enabling Permanent Governance Lockout — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

In `single` governance mode, the `checkConsistency` function validates that the **current** `GoverningNode` is in the council when processing a `governance.governingnode` vote, but never validates that the **proposed new** governing node address is in the council. This allows the governing node to ratify a vote transferring governance authority to an address that is not a council member and can therefore never become a block proposer, permanently locking all governance parameter changes.

### Finding Description

In `checkConsistency` at `kaiax/gov/headergov/impl/header.go` lines 159–178, when a `GovernanceGoverningNode` vote is processed in `single` mode, the code checks:

```go
if slices.Contains(council, params.GoverningNode) {
    return nil
}
return ErrGovNodeNotInValSetList
```

`params.GoverningNode` is the **current** governing node — not `vote.Value()`, which is the **proposed new** governing node. The proposed new address is never validated against the council. [1](#0-0) 

The `VerifyVote` function enforces that the voter (block proposer) must be in the council:

```go
if !slices.Contains(council, vote.Voter()) {
    return ErrInvalidKeyValue
}
``` [2](#0-1) 

After the Permissionless hardfork, `VerifyVote` additionally enforces that only the governing node may cast any vote:

```go
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [3](#0-2) 

The `Vote` API also enforces this at the RPC layer:

```go
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
``` [4](#0-3) 

The council membership of the proposed new governing node is never checked anywhere in the vote submission or verification path.

Additionally, `applyVote` in `kaiax/valset/impl/getter_council.go` explicitly protects the **current** governing node from being removed from the council:

```go
if address == governingNode {
    continue
}
``` [5](#0-4) 

But this protection applies to the current governing node, not to a newly-voted-in governing node that was never in the council to begin with.

### Impact Explanation

Once a `governance.governingnode` vote for a non-council address is ratified at an epoch boundary, the new `GoverningNode` is a non-council address. Since the council is the superset from which all proposers and committee members are drawn:

```
Council(N) = Council(N-1) + AddValidatorVotes(N-1) - RemoveValidatorVotes(N-1)
QualifiedValidators(N) = Council(N) - DemotedValidators(N)
Committee(N,R) ⊆ QualifiedValidators(N)
Proposer(N,R) ∈ Committee(N,R)
``` [6](#0-5) 

A non-council address can never be selected as a proposer. Since `VerifyVote` requires the voter to be the block proposer, and in `single` mode after Permissionless only the governing node may vote, the new governing node can never cast any vote. All governance parameter changes — including changing the governing node back to a valid address — are permanently blocked. This is an irreversible loss of on-chain governance control.

### Likelihood Explanation

The trigger requires the current governing node to cast a `governance.governingnode` vote with a non-council address as the value. This can happen by operator mistake (e.g., intending to add a new validator first, then transfer governance, but doing it in the wrong order), or by a compromised governing node key. The `checkConsistency` function provides no guard against this. The `Vote` API comment at line 79 even acknowledges a missing check: `// TODO-kaiax: add removevalidator vote check`, suggesting the validation surface is known to be incomplete. [7](#0-6) 

### Recommendation

In `checkConsistency`, for the `GovernanceGoverningNode` case, additionally verify that the proposed new governing node address (`vote.Value().(common.Address)`) is a member of the current council before accepting the vote:

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
    if !slices.Contains(council, params.GoverningNode) {
        return ErrGovNodeNotInValSetList
    }
    // NEW: also validate the proposed new governing node is in the council
    newGovNode := vote.Value().(common.Address)
    if !slices.Contains(council, newGovNode) {
        return ErrGovNodeNotInValSetList
    }
    return nil
``` [8](#0-7) 

### Proof of Concept

```
Step 0:
  GovernanceMode = "single"
  GoverningNode  = GOV_A  (GOV_A is in council)
  Council        = {GOV_A, V1, V2}

Step 1:
  GOV_A calls governance_vote("governance.governingnode", "0xDEAD...") 
  where 0xDEAD... is NOT in the council.
  
  checkConsistency passes because:
    - params.GoverningNode = GOV_A
    - slices.Contains(council, GOV_A) == true  ← checks CURRENT node, not new value
  
  Vote is stored in groupedVotes for the current epoch.

Step 2:
  At the next epoch block, the vote is ratified.
  header.Governance = {"governance.governingnode": "0xDEAD..."}
  GoverningNode is now 0xDEAD...

Step 3:
  0xDEAD... is not in the council.
  0xDEAD... can never be selected as a block proposer.
  VerifyVote requires voter == block proposer.
  In single mode, only GoverningNode (0xDEAD...) may vote.
  Therefore: no governance votes can ever be cast again.
  All governance parameters are permanently frozen.
  Governance control is irreversibly lost.
```

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L87-90)
```go
	// check if the voter is in council
	if !slices.Contains(council, vote.Voter()) {
		return ErrInvalidKeyValue
	}
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

**File:** kaiax/gov/headergov/impl/api.go (L61-63)
```go
	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/api.go (L79-79)
```go
	// TODO-kaiax: add removevalidator vote check
```

**File:** kaiax/valset/impl/getter_council.go (L243-246)
```go
	for _, address := range addresses {
		if address == governingNode {
			continue
		}
```

**File:** kaiax/valset/README.md (L11-17)
```markdown
- `Council(N)`: A set of validator addresses where the proposers and committee for the block N are selected from.
  - `DemotedValidators(N)`: Subset of the council not eligible to be committee and proposer.
  - `QualifiedValidators(N)`: Subset of the council eligible to be committee and proposer.
    - `Committee(N,R)`: Subset of qualified validators that can validate the block N at round R.
    - `Proposer(N,R)`: One of the qualified validators that will finalize and propose the block N at round R. Note that Proposer(N,R) is must be included in Committee(N,R).
  - The demoted and qualified validators are mutually exclusive and collecively form the council.
  - The qualified validators are often simply called "validators" as in `IstanbulExtra.Validators`.
```
