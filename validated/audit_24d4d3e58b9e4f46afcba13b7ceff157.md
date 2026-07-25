### Title
Last-Vote-Wins Ratification in `none`-Mode Header Governance Allows a Single GC Member to Unilaterally Override Collective Reward/Fee Parameter Votes — (`File: kaiax/gov/headergov/impl/header.go`)

### Summary

In Kaia's header governance system, when `governance.governancemode` is `none`, any Governance Council (GC) member can observe all on-chain votes cast by peers during an epoch and then cast a strategically timed last-minute vote to override them. The ratification rule — "the last vote in the epoch wins" — is implemented without any ordering protection, allowing a single semi-trusted GC member to unilaterally determine the outcome of parameters such as `reward.mintingamount`, `reward.ratio`, and `reward.kip82ratio`, which directly control KAIA minting and reward distribution.

### Finding Description

The `getExpectedGovernance` function in `kaiax/gov/headergov/impl/header.go` collects all votes from the previous epoch, sorts them by block number in ascending order, and iterates through them, calling `govs.Add` for each vote. Because `PartialParamSet.Add` overwrites any existing value for the same parameter name, the **last vote in block-number order unconditionally wins**:

```go
// kaiax/gov/headergov/impl/header.go lines 218-233
func (h *headerGovModule) getExpectedGovernance(blockNum uint64) headergov.GovData {
    prevEpochIdx := calcEpochIdx(blockNum, h.epoch) - 1
    prevEpochVotes := h.getVotesInEpoch(prevEpochIdx)
    govs := make(gov.PartialParamSet)

    sortedVoteBlocks := slices.Collect(maps.Keys(prevEpochVotes))
    slices.Sort(sortedVoteBlocks)          // ascending order

    for _, voteBlock := range sortedVoteBlocks {
        vote := prevEpochVotes[voteBlock]
        govs.Add(string(vote.Name()), vote.Value())  // last write wins
    }
    return headergov.NewGovData(govs)
}
```

This is explicitly documented in the README:

> `none` mode: all members of the GC can vote. For each governance parameter, **the last vote in the epoch will be ratified**.

All votes are permanently public — they are inscribed in `header.Vote` and queryable via the `governance_votes` RPC API. A GC member can therefore:

1. Monitor all votes cast by peers during the epoch via `governance_votes`.
2. Wait until they are scheduled to propose a block near the end of the epoch (each GC member proposes many blocks per epoch).
3. Cast a vote for any mutable parameter with their preferred value at that late block.
4. Because no subsequent vote can override theirs before the epoch closes, their value is ratified.

The voter-must-be-proposer constraint (`VerifyVote` checks `author == vote.Voter()`) does not prevent this — it only means the attacker must wait for their own proposer slot, which occurs naturally and predictably in the round-robin/weighted-random schedule.

### Impact Explanation

The affected mutable parameters include:

- `reward.mintingamount` — controls KAIA minted per block (inflation / total supply)
- `reward.ratio` — splits block rewards between proposer, stakers, KIF, and KEF
- `reward.kip82ratio` — splits staking rewards between proposer and stakers
- `governance.unitprice` — sets the gas price floor

A single GC member can set any of these to an extreme value (e.g., `reward.mintingamount = 0` to halt all minting, or `reward.ratio = "100/0/0"` to redirect all rewards to proposers). The ratified value takes effect at the start of the next epoch and governs all reward distributions for that entire epoch.

This matches the allowed impact: **unauthorized reward distribution** affecting KAIA and system-managed funds.

### Likelihood Explanation

- **Trigger**: Any single GC member operating in `none` mode. No majority collusion required.
- **Information advantage**: All prior votes are fully public on-chain and via RPC, so the attacker knows exactly what to override.
- **Proposer slot availability**: With N GC members and an epoch of E blocks, each member proposes approximately E/N blocks. The attacker can choose the latest one before the epoch boundary.
- **Scope**: `none` mode is a supported, code-reachable path. While Mainnet and Kairos are configured with `single` mode (immutable by genesis configuration), any Kaia-based network that deploys with `none` mode — including testnets, private chains, and future deployments — is fully exposed.

### Recommendation

1. **Short term**: In `none` mode, replace "last vote wins" with a majority-threshold or supermajority rule: a parameter change is ratified only if more than 50% (or 2/3) of GC members voted for the same value in the epoch. This eliminates the single-member override.
2. **Medium term**: Consider a commit-reveal scheme for votes so that GC members cannot observe each other's votes before committing their own.
3. **Long term**: Evaluate whether `none` mode should be deprecated in favor of contract governance (post-Kore), which can enforce richer voting semantics on-chain.

### Proof of Concept

**Setup**: A network with `governance.governancemode = "none"`, 5 GC members (A, B, C, D, E), epoch = 604800 blocks. Current `reward.mintingamount = 9.6 KAIA`.

**Attack**:

1. At block 100, GC member A proposes a block and casts `Vote: ("reward.mintingamount", 6.4 KAIA)`.
2. At block 200, GC member B casts `Vote: ("reward.mintingamount", 8.0 KAIA)`.
3. GC member E calls `governance_votes` and sees both votes.
4. E calculates that the epoch ends at block 604800. E checks the proposer schedule and finds they will propose block 604795.
5. At block 604795, E casts `Vote: ("reward.mintingamount", 0)`.
6. At block 604800 (epoch boundary), `getExpectedGovernance` sorts votes: [100→6.4 KAIA, 200→8.0 KAIA, 604795→0]. The last `govs.Add` call sets `reward.mintingamount = 0`.
7. The epoch-boundary block's `header.Governance` is ratified with `{"reward.mintingamount": 0}`.
8. Starting from block 604801, all block rewards are minted as 0 KAIA — stakers, proposers, KIF, and KEF receive nothing.

**Relevant code locations**:

- Ratification logic (last-write-wins): [1](#0-0) 
- Vote verification (proposer-only constraint, no timing guard): [2](#0-1) 
- Public vote query API (enables vote observation): [3](#0-2) 
- Documented "last vote wins" rule: [4](#0-3) 
- Mutable parameters affected (`reward.mintingamount`, `reward.ratio`, etc.): [5](#0-4)

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

**File:** kaiax/gov/headergov/impl/api.go (L89-109)
```go
func (api *headerGovAPI) Votes(num *rpc.BlockNumber) []VotesResponse {
	var blockNum uint64
	if num == nil || *num == rpc.LatestBlockNumber || *num == rpc.PendingBlockNumber {
		blockNum = api.h.Chain.CurrentBlock().NumberU64()
	} else {
		blockNum = num.Uint64()
	}

	epochIdx := calcEpochIdx(blockNum, api.h.epoch)
	votesInEpoch := api.h.getVotesInEpoch(epochIdx)

	ret := make([]VotesResponse, 0)
	for blockNum, vote := range votesInEpoch {
		ret = append(ret, VotesResponse{
			BlockNum: blockNum,
			Key:      string(vote.Name()),
			Value:    vote.Value(),
		})
	}
	return ret
}
```

**File:** kaiax/gov/headergov/README.md (L44-47)
```markdown
The ratification condition is determined by the `governance.governancemode` parameter. Mainnet and Kairos both operate in `single` mode. There are two governance modes:

- `none` mode: all members of the GC can vote. For each governance parameter, the last vote in the epoch will be ratified.
- `single` mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified in block order. For each governance parameter, the last vote in the epoch will be ratified.
```

**File:** kaiax/gov/README.md (L17-34)
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

```
