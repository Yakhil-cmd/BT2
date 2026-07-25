### Title
`checkConsistency` for `GovernanceGoverningNode` Validates the Wrong Address, Allowing Governance to Be Permanently Bricked — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

In `checkConsistency`, the `GovernanceGoverningNode` case checks whether the **current** governing node is in the council instead of checking whether the **proposed new** governing node is in the council. Because the current governing node can never be removed from the council (enforced by `applyVote`), this check is a permanent no-op. As a result, the governing node can ratify a vote that sets `governance.governingnode` to any arbitrary address — including one that is not a council member — permanently bricking single-mode governance with no recovery path.

### Finding Description

In `kaiax/gov/headergov/impl/header.go`, `checkConsistency` is called both from the `Vote` API and from `VerifyVote` during block processing. Its stated purpose is to verify that the vote **value** is consistent with current chain state.

For the `GovernanceGoverningNode` case the check reads:

```go
if slices.Contains(council, params.GoverningNode) {   // ← current governing node
    return nil
}
return ErrGovNodeNotInValSetList
```

`params.GoverningNode` is the **current** governing node, not `vote.Value().(common.Address)` which is the **proposed** new governing node. [1](#0-0) 

The `applyVote` function in the valset module explicitly skips any removal vote that targets the governing node:

```go
for _, address := range addresses {
    if address == governingNode {
        continue          // governing node is never removed
    }
    ...
}
``` [2](#0-1) 

Because the current governing node is therefore always in the council, `slices.Contains(council, params.GoverningNode)` is always `true`, and `ErrGovNodeNotInValSetList` is never returned. The check is a dead letter.

The correct check — analogous to how `Kip71LowerBoundBaseFee` and `Kip71UpperBoundBaseFee` validate `vote.Value()` — should be:

```go
if slices.Contains(council, vote.Value().(common.Address)) {
    return nil
}
return ErrGovNodeNotInValSetList
``` [3](#0-2) 

### Impact Explanation

If the governing node casts a `governance.governingnode` vote whose value is an address that is **not** in the council (e.g., a typo, a retired key, or an address that was removed after a prior governing-node rotation), the vote passes all checks, is ratified at the next epoch boundary, and takes effect at the epoch after that.

Once the new governing node address is not a council member:
- It cannot be selected as a block proposer, so it can never write `header.Vote`.
- No governance parameter can ever be changed again in `single` mode.
- Parameters controlling reward distribution (`reward.mintingamount`, `reward.ratio`, `reward.kip82ratio`), base-fee bounds, and committee size are permanently frozen at their last ratified values.
- There is no on-chain recovery path; the only remediation would require a hard fork.

The corrupted protected state is `governance.governingnode` stored in `header.Governance` at the epoch block, which propagates into every subsequent `GetParamSet` call and into reward, valset, and fee calculations. [4](#0-3) 

### Likelihood Explanation

The trigger requires the current governing node to submit a `governance.governingnode` vote with a non-council address. This is a privileged action. However, the scenario is reachable without malice:

1. Governing node A rotates to B (both in council).
2. A is subsequently removed from the council via `RemoveValidator`.
3. B later votes to rotate back to A (e.g., for key recovery), not realising A is no longer a council member.
4. The check passes (B is in council), the vote is ratified, and governance is bricked.

The epoch delay (up to one week on Mainnet/Kairos) between vote and ratification means the window to detect and cancel the vote is limited to the current epoch. [5](#0-4) 

### Recommendation

Replace `params.GoverningNode` with `vote.Value().(common.Address)` in the consistency check:

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
    // Validate the PROPOSED new governing node, not the current one.
    if slices.Contains(council, vote.Value().(common.Address)) {
        return nil
    }
    return ErrGovNodeNotInValSetList
```

This mirrors the pattern already used for `AddValidator`/`RemoveValidator`, which correctly inspects `vote.Value().([]common.Address)` rather than the current parameter value. [6](#0-5) 

### Proof of Concept

```
Epoch = 604800 blocks (Mainnet)

Block 0:       Genesis — GoverningNode = A, Council = {A, B, C}
Block 100:     A votes governance.governingnode = B
Block 604800:  Vote ratified; GoverningNode = B from block 1209600
Block 700000:  A votes RemoveValidator = A (A is no longer governing node, so removal is allowed)
Block 1209600: GoverningNode = B; A removed from council; Council = {B, C}
Block 1300000: B votes governance.governingnode = A
               checkConsistency: slices.Contains({B,C}, B) == true → passes
Block 1814400: Vote ratified; GoverningNode = A from block 2419200
Block 2419200: GoverningNode = A; A not in council
               A cannot be selected as proposer → can never write header.Vote
               Governance permanently frozen; no parameter can ever change again
``` [7](#0-6) [8](#0-7)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L41-52)
```go
	// if epoch block & vote exists in the last epoch, put Governance field.
	if header.Number.Uint64()%h.epoch == 0 {
		gov := h.getExpectedGovernance(header.Number.Uint64())
		if len(gov.Items()) > 0 {
			govBytes, err := gov.ToGovBytes()
			if err != nil {
				return err
			}
			header.Governance = govBytes
			logger.Debug("Prepare header with governance", "num", header.Number.Uint64(), "governance", hexutil.Encode(header.Governance))
		}
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

**File:** kaiax/gov/headergov/impl/header.go (L179-192)
```go
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

**File:** kaiax/valset/impl/getter_council.go (L243-246)
```go
	for _, address := range addresses {
		if address == governingNode {
			continue
		}
```

**File:** kaiax/gov/headergov/README.md (L49-50)
```markdown
Parameter change ratified at `k*epoch` block takes effect starting from `(k+1)*epoch` block.
It is worth noting that the effective time of the ratification is `(k+1)*epoch + 1` before Kore.
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
