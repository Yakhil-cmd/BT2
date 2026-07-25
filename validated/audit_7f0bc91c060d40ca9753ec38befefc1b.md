After extensive searching across governance, reward, valset, bridge, and consensus code, I found a valid analog.

---

### Title
`getExpectedGovernance` Ratifies Non-Governing-Node Votes in Single Mode, Bypassing `VerifyVote`'s Voter-Eligibility Guard — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary
In single governance mode, `VerifyVote` enforces the governing-node restriction **only after the Permissionless hardfork**. Pre-Permissionless, any council member who becomes a block proposer can write a vote to `header.Vote`, which passes `VerifyVote` and is stored. The `getExpectedGovernance` function then ratifies **all** stored votes from the epoch without filtering by voter eligibility, allowing a non-governing council member to change protected governance parameters — including `governance.governingnode` (full privilege escalation), `reward.mintingamount`, and `governance.unitprice`.

### Finding Description

**The incomplete guard in `VerifyVote`:**

`VerifyVote` checks that the voter is in council and is the block proposer, but the governing-node restriction is gated behind `IsPermissionlessForkEnabled`:

```go
// In single mode, only the governing node can write header.Vote after Permissionless.
params := h.GetParamSet(blockNum)
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
```

Pre-Permissionless, in single mode, any council member who is the current block proposer passes all three checks (in-council, is-proposer, consistency) and their vote is accepted. [1](#0-0) 

**The "move-all" analog — `getExpectedGovernance` ignores voter eligibility entirely:**

At every epoch boundary, `getExpectedGovernance` collects **all** votes stored in the previous epoch and ratifies them, with no filter on who cast them:

```go
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
    prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
    prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
    govs := make(gov.PartialParamSet)
    sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
    slices.Sort(sortedVoteBlocks)
    for _, voteBlock := range sortedVoteBlocks {
        vote := prevEpochVotes[voteBlock]
        govs.Add(string(vote.Name()), vote.Value())  // no voter check
    }
    return headergov.NewGovData(govs)
}
``` [2](#0-1) 

The README explicitly states: *"single mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified."* `getExpectedGovernance` violates this invariant by ratifying votes from any council member. [3](#0-2) 

**`VerifyGov` provides no additional protection** — it only checks that the header's governance data matches what `getExpectedGovernance` computes, so it accepts the tainted ratification: [4](#0-3) 

**`HandleVote` stores every vote that passes `VerifyVote`**, with no voter-eligibility filter: [5](#0-4) 

The API-level guard (`governance_vote` checks `voter != GoverningNode`) is irrelevant because a malicious council member controlling their node binary can write arbitrary `header.Vote` bytes directly in `PrepareHeader`, bypassing the API entirely. [6](#0-5) 

### Impact Explanation

A malicious non-governing council member can unilaterally change any governance parameter in single mode (pre-Permissionless), including:

- **`governance.governingnode`** → change to attacker's address, seizing full governance control permanently.
- **`reward.mintingamount`** → alter KAIA inflation, corrupting per-block reward distribution (`FinalizeState` → `state.AddBalance`).
- **`governance.unitprice`** → change the base gas price, affecting all transaction fee accounting.

This is a governance privilege escalation that changes protected chain state and asset ownership (KAIA reward distribution). [7](#0-6) 

### Likelihood Explanation

- **Trigger**: A council member (semi-trusted, not the governing node) who becomes a block proposer — this happens naturally under round-robin or weighted-random proposer selection.
- **Mechanism**: The attacker modifies their node binary to write a crafted `header.Vote` in `PrepareHeader`, bypassing the API-level guard.
- **Scope**: Chains running in `single` governance mode before the Permissionless hardfork, or any chain that has not enabled `PermissionlessCompatibleBlock`. Kaia Mainnet and Kairos both operate in `single` mode.
- **No collusion required**: A single malicious council member suffices.

### Recommendation

1. **Remove the `IsPermissionlessForkEnabled` gate** from the governing-node check in `VerifyVote` so it applies in all forks:
   ```go
   if params.GovernanceMode == "single" && vote.Voter() != params.GoverningNode {
       return ErrVotePermissionDenied
   }
   ```
2. **Add a voter-eligibility filter in `getExpectedGovernance`**: in single mode, skip any vote whose `Voter()` is not the current governing node, providing defense-in-depth even if a vote somehow passes `VerifyVote`.

### Proof of Concept

```
Setup: single mode, epoch=1000, governing node = A, council = {A, B, C}

Block 500: council member B is the proposer.
  B's node binary writes header.Vote = vote("governance.governingnode", B_address)
  VerifyVote(block 500):
    - vote.Voter() == B  ∈ council  ✓
    - author(block 500) == B        ✓
    - IsPermissionlessForkEnabled == false → governing-node check SKIPPED ✓
    - checkConsistency: current GoverningNode A ∈ council ✓
  → vote accepted, HandleVote stores it.

Block 1000 (epoch boundary): any proposer writes header.Governance.
  getExpectedGovernance(1000):
    prevEpochVotes = {500: vote("governance.governingnode", B)}
    → govs = {"governance.governingnode": B}   // no voter filter
  VerifyGov: header.Governance matches expected → accepted.

Block 1001+: GetParamSet returns GoverningNode = B.
  B now has exclusive governance authority in single mode.
  B can vote to change reward.mintingamount, governance.unitprice, etc.
  All subsequent VerifyVote calls enforce B as the governing node.
```

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L101-109)
```go
	// In single mode, only the governing node can write header.Vote after Permissionless.
	params := h.GetParamSet(blockNum)
	if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
		params.GovernanceMode == "single" &&
		vote.Voter() != params.GoverningNode {
		return ErrVotePermissionDenied
	}

	return h.checkConsistency(blockNum, vote)
```

**File:** kaiax/gov/headergov/impl/header.go (L118-154)
```go
func (h *headerGovModule) VerifyGov(header *types.Header) error {
	// (1)
	if header.Number.Uint64()%h.epoch != 0 {
		if len(header.Governance) > 0 {
			logger.Error("governance is not allowed in non-epoch block", "num", header.Number.Uint64())
			return ErrGovInNonEpochBlock
		} else {
			return nil
		}
	}

	// (2), (3)
	expected := h.getExpectedGovernance(header.Number.Uint64())
	if len(header.Governance) == 0 {
		if len(expected.Items()) != 0 {
			return ErrGovVerification
		}

		return nil
	}

	// (4)
	var gb headergov.GovBytes = header.Governance
	actual, err := gb.ToGovData()
	if err != nil {
		logger.Error("DeserializeHeaderGov error", "num", header.Number.Uint64(), "governance", gb, "err", err)
		return err
	}

	// (5)
	if !reflect.DeepEqual(expected, actual) {
		logger.Error("Governance mismatch", "expected", expected, "actual", actual)
		return ErrGovVerification
	}

	return nil
}
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

**File:** kaiax/gov/headergov/README.md (L44-47)
```markdown
The ratification condition is determined by the `governance.governancemode` parameter. Mainnet and Kairos both operate in `single` mode. There are two governance modes:

- `none` mode: all members of the GC can vote. For each governance parameter, the last vote in the epoch will be ratified.
- `single` mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified in block order. For each governance parameter, the last vote in the epoch will be ratified.
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

**File:** kaiax/gov/headergov/impl/api.go (L53-63)
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
```

**File:** kaiax/reward/impl/blockstate.go (L46-56)
```go
	spec, err := r.GetDeferredReward(header, txs, receipts)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	for addr, amount := range spec.Rewards {
		state.AddBalance(addr, amount)
	}
	return nil
```
