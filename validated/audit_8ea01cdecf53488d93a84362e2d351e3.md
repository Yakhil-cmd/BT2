### Title
Non-Governing Council Member Can Cast Ratified Governance Votes in `single` Mode Pre-Permissionless — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

`VerifyVote` in `kaiax/gov/headergov/impl/header.go` only enforces the "single mode → governing node only" restriction **after** the Permissionless hardfork. Pre-Permissionless, any council member who becomes a block proposer can embed a governance vote in their block header, and that vote is stored and ratified at the next epoch block without any governing-node filter. This is the direct analog of the external bug: a "collector" (non-governing council member) can perform a "creator" (governing node) action, corrupting protected governance state.

---

### Finding Description

The `IStory` analog in Kaia is the header-governance voting system. In `single` governance mode the protocol specification states that **only the governing node** may cast votes:

> *"single mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote."*
> — `kaiax/gov/headergov/README.md` line 47

The `Vote` API enforces this unconditionally:

```go
// kaiax/gov/headergov/impl/api.go:61-63
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
```

But `VerifyVote` — the on-chain enforcement path called during block import — gates the same check behind `IsPermissionlessForkEnabled`:

```go
// kaiax/gov/headergov/impl/header.go:101-107
// In single mode, only the governing node can write header.Vote after Permissionless.
params := h.GetParamSet(blockNum)
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
```

Pre-Permissionless, the only checks that run are:

1. Voter is in the council (line 88).
2. Voter is the block proposer (line 97).

A council member who is **not** the governing node satisfies both checks whenever they are selected as proposer. Their vote therefore passes `VerifyVote`, is accepted into the chain, and is stored by `HandleVote` → `AddVote` into `groupedVotes`.

At the next epoch block, `getExpectedGovernance` collects **all** stored votes with no governing-node filter:

```go
// kaiax/gov/headergov/impl/header.go:218-233
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
    prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
    prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
    govs := make(gov.PartialParamSet)
    for _, voteBlock := range sortedVoteBlocks {
        vote := prevEpochVotes[voteBlock]
        govs.Add(string(vote.Name()), vote.Value())   // no voter identity check
    }
    return headergov.NewGovData(govs)
}
```

`VerifyGov` then accepts the epoch block only if its `header.Governance` matches this locally-computed expected governance (line 148). Because every node computes the same unfiltered set, the non-governing node's vote is ratified and takes effect at the next epoch.

The test suite explicitly documents and accepts this behaviour:

```go
// kaiax/gov/headergov/impl/header_test.go:126-133
t.Run("pre-permissionless allows non-governing node", func(t *testing.T) {
    config.PermissionlessCompatibleBlock = nil
    ...
    err = h.VerifyVote(&types.Header{Number: big.NewInt(1), Vote: vb, Extra: extra})
    assert.NoError(t, err)   // non-governing vote accepted
})
```

---

### Impact Explanation

A non-governing council member can unilaterally ratify changes to any governance parameter, including:

- `reward.mintingamount` — alters KAIA minting per block, directly affecting total KAIA issuance.
- `reward.ratio` — redirects the split of block rewards among validators, KIF, and KEF.
- `governance.unitprice` — changes the minimum gas price, affecting all transaction fees.
- `governance.governingnode` — transfers the governing-node role to the attacker's address, permanently seizing governance control.
- `governance.addvalidator` / `governance.removevalidator` — manipulates the validator set.

These are protected chain-state values. Corrupting them constitutes governance privilege escalation with direct KAIA reward-distribution and fee-accounting impact.

---

### Likelihood Explanation

- **Precondition 1:** The chain is pre-Permissionless fork (`PermissionlessCompatibleBlock` is nil or not yet reached). Chains that have not yet activated the Permissionless hardfork are fully exposed.
- **Precondition 2:** Governance mode is `single` (Kaia Mainnet and Kairos both use `single` mode).
- **Precondition 3:** The attacker controls a council member address that is **not** the governing node. In a multi-validator council this is the normal case for all validators except one.
- **Trigger:** The attacker simply waits to be selected as block proposer (which occurs naturally in round-robin or weighted-random rotation) and includes a crafted `header.Vote` in their block. No additional privilege is required.

No majority collusion is needed; a single non-governing council member suffices.

---

### Recommendation

Remove the `IsPermissionlessForkEnabled` guard from the single-mode voter check in `VerifyVote` so that the restriction applies on all blocks, not only post-Permissionless ones:

```go
// kaiax/gov/headergov/impl/header.go
// Before (current):
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}

// After (fixed):
if params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
```

Additionally, `getExpectedGovernance` should filter collected votes by the governing node when the mode is `single`, so that even if a non-governing vote somehow reaches storage it cannot be ratified.

---

### Proof of Concept

**Setup:** A chain with `governance.governancemode = "single"`, `governance.governingnode = A`, council = `{A, B}`, `PermissionlessCompatibleBlock = nil` (pre-Permissionless).

**Attack steps:**

1. Council member `B` (not the governing node) calls `governance_vote("reward.mintingamount", <attacker_value>)` on their node. The API rejects it with `ErrVotePermissionDenied` (line 61-63 of `api.go`).

2. `B` bypasses the API and directly crafts a block header with `header.Vote = RLP(voter=B, name="reward.mintingamount", value=<attacker_value>)`.

3. When `B` is selected as proposer, they broadcast this block. Every peer calls `VerifyVote`:
   - `B` is in council ✓
   - `B` is the block author ✓
   - `IsPermissionlessForkEnabled` is false → the governing-node check is **skipped** ✓
   - `checkConsistency` for `RewardMintingAmount` returns `nil` ✓
   - Vote passes.

4. `PostInsertBlock` calls `HandleVote` → `AddVote`, storing the vote in `groupedVotes[epochIdx][blockNum]`.

5. At the next epoch block, `getExpectedGovernance` collects `B`'s vote (no voter filter). The epoch block's `header.Governance` encodes `{"reward.mintingamount": <attacker_value>}`.

6. `VerifyGov` accepts the epoch block because `expected == actual`.

7. `HandleGov` → `AddGov` persists the ratified governance. From the next epoch onward, `GetParamSet` returns `MintingAmount = <attacker_value>`, corrupting KAIA reward distribution for all subsequent blocks. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** kaiax/gov/headergov/impl/api.go (L61-63)
```go
	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/header_test.go (L123-143)
```go
func TestVerifyVote_SingleMode(t *testing.T) {
	config := getTestChainConfig()
	config.Governance.GoverningNode = common.Address{2} // validVoter is the proposer, but not governing node
	t.Run("pre-permissionless allows non-governing node", func(t *testing.T) {
		config.PermissionlessCompatibleBlock = nil
		h := newHeaderGovModule(t, config)
		vote := headergov.NewVoteData(validVoter, string(gov.GovernanceUnitPrice), uint64(100))
		vb, err := vote.ToVoteBytes()
		require.NoError(t, err)
		err = h.VerifyVote(&types.Header{Number: big.NewInt(1), Vote: vb, Extra: extra})
		assert.NoError(t, err)
	})
	t.Run("post-permissionless requires governing node", func(t *testing.T) {
		config.PermissionlessCompatibleBlock = common.Big0
		h := newHeaderGovModule(t, config)
		vote := headergov.NewVoteData(validVoter, string(gov.GovernanceUnitPrice), uint64(100))
		vb, err := vote.ToVoteBytes()
		require.NoError(t, err)
		err = h.VerifyVote(&types.Header{Number: big.NewInt(1), Vote: vb, Extra: extra})
		assert.Equal(t, ErrVotePermissionDenied, err)
	})
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
