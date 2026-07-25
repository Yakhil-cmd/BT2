Let me check the execution path to confirm how accepted votes are stored and ratified.

### Title
Pre-Permissionless-Fork Single-Mode Governance Bypass: Non-Governing Council Member Can Cast Unauthorized Votes — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

In `single` governance mode, the invariant is that only the governing node may cast governance votes. However, the enforcement of this invariant in `VerifyVote` is gated on `IsPermissionlessForkEnabled`, leaving pre-Permissionless-fork chains completely unprotected. Any non-governing council member who is the block proposer for a given block can embed an unauthorized governance vote in the block header, have it accepted by all honest nodes, and see it ratified at the next epoch boundary — changing protected chain parameters such as `reward.ratio` or `reward.mintingamount`.

---

### Finding Description

`VerifyVote` enforces three checks before accepting a header vote:

1. The voter is in the council.
2. The voter is the block proposer (cryptographically verified via `Author(header)`).
3. **In single mode, the voter is the governing node — but only after `IsPermissionlessForkEnabled`.** [1](#0-0) 

The comment on line 101 itself reads *"only the governing node can write header.Vote **after Permissionless**"*, confirming the restriction is intentionally absent before that fork. Before the Permissionless fork, checks 1 and 2 pass for any council member who is the current block proposer, and check 3 is never evaluated.

Once `VerifyVote` returns `nil`, the vote is stored into `groupedVotes` during block execution. At the next epoch block, `getExpectedGovernance` aggregates all votes from the previous epoch — including the unauthorized one — and the epoch block proposer embeds the result in `header.Governance`. [2](#0-1) 

`VerifyGov` then requires every honest node to accept the epoch block only if its `Governance` field exactly matches this locally-derived expected value, which now includes the unauthorized vote. All honest nodes ratify the corrupted parameter. [3](#0-2) 

---

### Impact Explanation

The attacker can change any governance parameter accepted by `checkConsistency` without restriction, including:

- `reward.ratio` — splits block reward between proposer, stakers, and KIF/KEF.
- `reward.mintingamount` — controls newly minted KAIA per block.
- `reward.minimumstake`, `reward.kip82ratio`, `governance.unitprice`, etc. [4](#0-3) 

These changes take effect at the next epoch and alter reward distribution for all subsequent blocks — an unauthorized, persistent change to protected chain state and asset flow.

---

### Likelihood Explanation

- Requires the attacker to be a non-governing council member (staked validator). This is a semi-trusted but not fully trusted role; it does not require majority collusion or the governing node's key.
- In Kaia's Istanbul BFT consensus, council members rotate as block proposers, so any council member will eventually propose a block and can embed the vote.
- Only one malicious council member is needed; no coordination with others is required.
- The window is every pre-Permissionless-fork block where the attacker is the proposer.

---

### Recommendation

Remove the `IsPermissionlessForkEnabled` gate from the single-mode voter restriction. The check should apply unconditionally whenever `GovernanceMode == "single"`:

```go
// Before fix (lines 103-107):
if h.ChainConfig.IsPermissionlessForkEnabled(...) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}

// After fix:
if params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [1](#0-0) 

---

### Proof of Concept

1. Configure a chain with `GovernanceMode = "single"`, `GoverningNode = A`, and council `[A, B]`, with no Permissionless fork block set (or a future block number).
2. Node B waits until it is selected as block proposer for block N.
3. Node B constructs block N with `header.Vote` encoding a vote for `reward.mintingamount = <attacker-chosen value>`, signed by B.
4. All honest nodes call `VerifyVote`:
   - B is in council → passes.
   - `Author(header) == B == vote.Voter()` → passes.
   - `IsPermissionlessForkEnabled` is false → single-mode check is skipped entirely.
   - `checkConsistency` for `RewardMintingAmount` returns `nil` unconditionally.
5. Block N is accepted and the vote is stored in `groupedVotes`.
6. At the next epoch block M, `getExpectedGovernance` returns the unauthorized vote; the epoch block's `Governance` field encodes it; `VerifyGov` accepts it on all honest nodes.
7. From epoch M onward, `reward.mintingamount` is the attacker-chosen value, altering KAIA minting for all subsequent blocks.

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

**File:** kaiax/gov/headergov/impl/header.go (L118-153)
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
```

**File:** kaiax/gov/headergov/impl/header.go (L205-211)
```go
	case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, gov.GovernanceUnitPrice,
		gov.IstanbulCommitteeSize, gov.IstanbulEpoch, gov.IstanbulPolicy,
		gov.Kip71BaseFeeDenominator, gov.Kip71GasTarget, gov.Kip71MaxBlockGasUsedForBaseFee,
		gov.RewardDeferredTxFee, gov.RewardKip82Ratio, gov.RewardMintingAmount, gov.RewardMinimumStake,
		gov.RewardProposerUpdateInterval, gov.RewardRatio, gov.RewardStakingRewardThreshold,
		gov.RewardStakingUpdateInterval, gov.RewardUseFlexReward, gov.RewardUseGiniCoeff:
		return nil
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
