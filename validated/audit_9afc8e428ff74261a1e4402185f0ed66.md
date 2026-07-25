After thorough investigation of the Kaia codebase, I found a genuine analog to the reported bug pattern.

---

### Title
Governance Consistency Check Validates Wrong Address, Allowing `GovernanceGoverningNode` Vote to Set a Non-Council Address — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

In `checkConsistency`, the `GovernanceGoverningNode` case checks whether the **current** governing node is in the council, instead of checking whether the **proposed new** governing node (the vote value) is in the council. This mirrors the external bug exactly: the wrong identifier is used in a guard check, making the guard a near-no-op that passes in all normal circumstances, while the intended invariant — that the new governing node must be a council member — is never enforced.

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` is called from both `VerifyVote` (block validation) and the `Vote` API to enforce that a `GovernanceGoverningNode` vote is consistent with chain state. The relevant branch is:

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
    if slices.Contains(council, params.GoverningNode) {  // ← checks CURRENT node
        return nil
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

The check `slices.Contains(council, params.GoverningNode)` tests whether the **current** governing node (`params.GoverningNode`) is in the council. It should instead test whether the **new** governing node (`vote.Value().(common.Address)`) is in the council. Because the current governing node is almost always a council member (it is already verified to be the block proposer at line 97), this check passes unconditionally in practice, and the intended guard is never applied. [2](#0-1) 

The correct check would be:
```go
newGoverningNode := vote.Value().(common.Address)
if !slices.Contains(council, newGoverningNode) {
    return ErrGovNodeNotInValSetList
}
```

The existing unit test for this path (`"valid governingnode"`) sets `validVoter` as both the current governing node and the vote value, so it does not distinguish between checking the current vs. the new address and does not catch the bug. [3](#0-2) 

### Impact Explanation

In `single` governance mode (the mode used by Kaia Mainnet and Kairos), the governing node controls all governance parameter changes: `reward.mintingamount`, `reward.ratio`, `reward.kip82ratio`, `governance.unitprice`, and others that directly affect KAIA reward distribution and validator set composition. [4](#0-3) 

If the governing node is changed to an address that is not in the council:

1. **Governance lock**: The new governing node cannot be a block proposer (only council members can propose blocks), so it can never include a `header.Vote` in a block. All future governance votes are permanently blocked.
2. **Governance takeover**: If the attacker controls the non-council address, they can later add it to the council via a separate mechanism and then exercise exclusive governance control.

Both outcomes constitute a **governance privilege escalation that changes protected chain state**, matching the allowed impact gate.

### Likelihood Explanation

The trigger requires the current governing node (a privileged role) to cast a `GovernanceGoverningNode` vote for a non-council address. This could occur:
- Accidentally (operator error, wrong address pasted)
- Maliciously (a compromised or colluding governing node)

The governing node is a semi-trusted actor (not majority-validator collusion), and the bug removes the on-chain guard that was supposed to prevent this mistake. The `Vote` API and `VerifyVote` both call `checkConsistency`, so neither the API-level nor the block-validation path catches the invalid vote. [5](#0-4) [6](#0-5) 

### Recommendation

Replace the check on the current governing node with a check on the proposed new governing node:

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
    newGoverningNode := vote.Value().(common.Address)
    if !slices.Contains(council, newGoverningNode) {
        return ErrGovNodeNotInValSetList
    }
    return nil
```

Add a unit test that votes to change the governing node to an address not in the council and asserts `ErrGovNodeNotInValSetList` is returned.

### Proof of Concept

1. Chain is in `single` governance mode. Current governing node is `GN` (a council member).
2. `GN` calls `governance_vote("governance.governingnode", "0xDeadAddress")` where `0xDeadAddress` is not in the council.
3. `checkConsistency` is called. It checks `slices.Contains(council, params.GoverningNode)` — i.e., whether `GN` is in the council. `GN` is in the council, so the function returns `nil` (valid).
4. The vote is queued and included in a block header by `GN` when it next proposes.
5. At the next epoch boundary, `VerifyGov` accepts the `header.Governance` containing `{"governance.governingnode": "0xDeadAddress"}` because `checkConsistency` passed during `VerifyVote`.
6. `PostInsertBlock` → `HandleGov` ratifies the new governing node as `0xDeadAddress`.
7. From this point, only `0xDeadAddress` can cast governance votes. Since it is not a council member, it can never be a block proposer, and governance is permanently locked. All future reward ratio, minting amount, and validator set governance changes are blocked. [7](#0-6) [8](#0-7)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L77-109)
```go
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

**File:** kaiax/gov/headergov/impl/header_test.go (L81-81)
```go
		{desc: "valid governingnode", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGoverningNode), validVoter.Hex()), expectedError: nil},
```

**File:** kaiax/gov/headergov/impl/api.go (L70-77)
```go
	if gov.DeprecatedAt(vote.Name(), api.h.ChainConfig.Rules(new(big.Int).SetUint64(nextBlock))) {
		return "", ErrDeprecatedVote
	}

	err := api.h.checkConsistency(nextBlock, vote)
	if err != nil {
		return "", err
	}
```

**File:** kaiax/gov/headergov/impl/execution.go (L57-63)
```go
func (h *headerGovModule) HandleGov(blockNum uint64, gov headergov.GovData) error {
	h.AddGov(blockNum, gov)

	data := h.GovBlockNums()
	WriteGovDataBlockNums(h.ChainKv, data)
	return nil
}
```
