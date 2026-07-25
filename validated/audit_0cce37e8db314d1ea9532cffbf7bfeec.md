### Title
Pre-Permissionless `VerifyVote` Missing Single-Mode Governing-Node Restriction Allows Any Council Member to Hijack Governance Authority — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

`headerGovModule.VerifyVote` only enforces the single-mode governing-node restriction **after** `IsPermissionlessForkEnabled`. On chains where `PermissionlessCompatibleBlock=nil` and `GovernanceMode='single'`, any council member who is selected as block proposer can embed a governance vote (including `governance.governingnode=<self>`) that passes all validation, gets stored by `HandleVote`, and is ratified at the epoch boundary — permanently replacing the `GoverningNode` parameter.

---

### Finding Description

The guard in `VerifyVote` is conditioned on `IsPermissionlessForkEnabled`: [1](#0-0) 

The comment on line 101 explicitly acknowledges this is an "after Permissionless" restriction. Pre-Permissionless, the only checks are:

1. Voter is in council — satisfied by any legitimate validator.
2. Voter is the block proposer — satisfied whenever the attacker's turn comes in IBFT rotation.
3. `checkConsistency` for `GovernanceGoverningNode` — checks only that the **current** `GoverningNode` is in council, not that the **voter** is the governing node. [2](#0-1) 

Once `VerifyVote` passes, `PostInsertBlock` calls `HandleVote` unconditionally: [3](#0-2) 

`AddVote` stores the vote indexed by block number with no majority requirement — a single vote per epoch suffices: [4](#0-3) 

At the epoch boundary, `getExpectedGovernance` collects all stored votes from the previous epoch (last writer wins per parameter): [5](#0-4) 

`VerifyGov` then **requires** the epoch block to include this governance data — any proposer who omits it causes a verification failure, so the corrupted `GoverningNode` is forced into the canonical chain: [6](#0-5) 

`HandleGov` → `AddGov` → `GovsToHistory` persists the new `GoverningNode` into the history, and `GetParamSet` returns it for all subsequent blocks: [7](#0-6) 

---

### Impact Explanation

After the epoch boundary, `GetParamSet(blockNum).GoverningNode == addrB` for all `blockNum` in the new epoch. The attacker now holds the governing-node role and can:

- Cast further governance votes unopposed (the single-mode check post-Permissionless will now pass for them).
- Change `GovernanceMode`, `GoverningNode`, validator set membership, reward ratios, minting amounts, and any other header-governance-controlled parameter.

This is a permanent, chain-state-level governance privilege escalation. The original governing node loses all authority without any key compromise or majority-validator collusion.

---

### Likelihood Explanation

The attacker only needs to be a council member (a legitimate validator). In IBFT, every council member is eventually selected as block proposer through the normal round-robin or weighted rotation. No special access, no compromised keys, no external service — just waiting for a proposer slot and embedding a vote in the block header.

---

### Recommendation

Remove the `IsPermissionlessForkEnabled` condition from the single-mode governing-node check in `VerifyVote`. The restriction should apply unconditionally whenever `GovernanceMode == "single"`:

```go
// Before (buggy):
if h.ChainConfig.IsPermissionlessForkEnabled(...) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}

// After (fixed):
if params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [1](#0-0) 

---

### Proof of Concept

```
Setup:
  PermissionlessCompatibleBlock = nil   // pre-Permissionless chain
  GovernanceMode = "single"
  GoverningNode  = addrA
  Council        = [addrA, addrB]
  epoch          = 30

Step 1: addrB is selected as block proposer for block N (N < epoch boundary).
        addrB embeds Vote{voter=addrB, name="governance.governingnode", value=addrB}
        in the block header.

Step 2: VerifyVote(header):
  - addrB in council?                          → YES (pass)
  - Author(header) == addrB?                   → YES (pass)
  - IsPermissionlessForkEnabled? → false        → single-mode check SKIPPED
  - checkConsistency: addrA in council?         → YES (pass)
  → VerifyVote returns nil (no error)

Step 3: PostInsertBlock → HandleVote → AddVote stores
        groupedVotes[epochIdx][N] = Vote{governingnode=addrB}

Step 4: At block (epoch), getExpectedGovernance collects the vote.
        VerifyGov requires Governance field = {governingnode: addrB}.
        HandleGov → AddGov → GovsToHistory persists GoverningNode=addrB.

Step 5: GetParamSet(epoch+1).GoverningNode == addrB  ✓
        addrB is now the governing node; addrA has lost governance authority.
```

### Citations

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

**File:** kaiax/gov/headergov/impl/header.go (L129-137)
```go
	// (2), (3)
	expected := h.getExpectedGovernance(header.Number.Uint64())
	if len(header.Governance) == 0 {
		if len(expected.Items()) != 0 {
			return ErrGovVerification
		}

		return nil
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

**File:** kaiax/gov/headergov/impl/header.go (L218-233)
```go
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
	prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
	prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
	govs := make(gov.PartialParamSet)

	sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
	slices.Sort(sortedVoteBlocks)

	for _, voteBlock := range sortedVoteBlocks {
		vote := prevEpochVotes[voteBlock]
		govs.Add(string(vote.Name()), vote.Value())
	}

	// assert(len(headergov.NewGovData(govs).Items()) == len(govs))
	return headergov.NewGovData(govs)
}
```

**File:** kaiax/gov/headergov/impl/execution.go (L44-55)
```go
func (h *headerGovModule) HandleVote(blockNum uint64, vote headergov.VoteData) error {
	// if governance vote (i.e., not validator vote), add to vote
	if _, ok := gov.Params[vote.Name()]; ok {
		h.AddVote(blockNum, vote)
		InsertVoteDataBlockNum(h.ChainKv, blockNum)
	}

	// if the vote was mine, remove it.
	h.removeMyVote(vote)

	return nil
}
```

**File:** kaiax/gov/headergov/impl/execution.go (L73-83)
```go
func (h *headerGovModule) AddVote(blockNum uint64, vote headergov.VoteData) {
	h.mu.Lock()
	defer h.mu.Unlock()

	epochIdx := calcEpochIdx(blockNum, h.epoch)

	if _, ok := h.groupedVotes[epochIdx]; !ok {
		h.groupedVotes[epochIdx] = make(headergov.VotesInEpoch)
	}
	h.groupedVotes[epochIdx][blockNum] = vote
}
```

**File:** kaiax/gov/headergov/history.go (L12-33)
```go
func GovsToHistory(govs map[uint64]GovData) History {
	gh := make(map[uint64]gov.ParamSet)

	// we must ensure that gov history is not empty
	gh[0] = *gov.GetDefaultGovernanceParamSet()

	sortedNums := make([]uint64, 0, len(govs))
	for num := range govs {
		sortedNums = append(sortedNums, num)
	}
	slices.Sort(sortedNums)

	gp := *gov.GetDefaultGovernanceParamSet()
	for _, num := range sortedNums {
		govData := govs[num]
		if err := gp.SetFromMap(govData.Items()); err != nil {
			continue
		}
		gh[num] = gp
	}

	return gh
```
