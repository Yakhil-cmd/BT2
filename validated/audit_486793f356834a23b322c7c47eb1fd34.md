### Title
Non-Governing Council Member Can Cast Unauthorized Governance Votes in Single Mode Before Permissionless Fork — (File: `kaiax/gov/headergov/impl/header.go`)

### Summary
In `single` governance mode, `VerifyVote` only enforces the governing-node-only restriction when `IsPermissionlessForkEnabled` returns true. Before the Permissionless fork, any council member who becomes a block proposer can embed a governance vote in `header.Vote` that passes block-level validation and is ratified at the next epoch block — allowing unauthorized changes to `reward.mintingamount`, `reward.ratio`, `governance.governingnode`, and the validator set.

### Finding Description

`VerifyVote` in `kaiax/gov/headergov/impl/header.go` gates the single-mode governing-node check behind the Permissionless fork flag:

```go
// In single mode, only the governing node can write header.Vote after Permissionless.
params := h.GetParamSet(blockNum)
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [1](#0-0) 

When `PermissionlessCompatibleBlock` is `nil` or the current block is before that height, `IsPermissionlessForkEnabled` returns `false` and the entire governing-node check is skipped. Any council member who is the block proposer can embed an arbitrary governance vote in `header.Vote` and it will pass `VerifyVote`.

The `governance_vote` RPC API does apply the restriction unconditionally:

```go
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
``` [2](#0-1) 

But this is only an API-level guard. A malicious validator running modified node software can bypass the API entirely and directly write the vote into `header.Vote` during `PrepareHeader`. The block-level `VerifyVote` will accept it.

The test suite explicitly confirms this behavior is reachable:

```go
t.Run("pre-permissionless allows non-governing node", func(t *testing.T) {
    config.PermissionlessCompatibleBlock = nil
    ...
    err = h.VerifyVote(&types.Header{Number: big.NewInt(1), Vote: vb, Extra: extra})
    assert.NoError(t, err) // vote accepted despite non-governing voter in single mode
})
``` [3](#0-2) 

Once accepted, the vote is stored via `HandleVote` and ratified at the next epoch block via `getExpectedGovernance` → `VerifyGov`, which only checks that the ratified set matches the collected votes — it does not re-check voter authority. [4](#0-3) 

### Impact Explanation

A malicious council member can ratify any of the following governance parameters without authorization:

- `reward.mintingamount` — set to 0 (halt inflation) or an arbitrarily large value (hyperinflation of KAIA)
- `reward.ratio` — redirect the entire block reward to validators (e.g., `100/0/0`), starving KIF/KEF funds
- `governance.governingnode` — transfer governance control to an attacker-controlled address
- `governance.addvalidator` / `governance.removevalidator` — manipulate the validator set [5](#0-4) 

All of these directly affect KAIA token distribution and protected governance state. The `FinalizeState` reward module reads `reward.mintingamount` and `reward.ratio` from the ratified parameter set every block and mints/distributes accordingly. [6](#0-5) 

### Likelihood Explanation

- **Attacker role**: A council member (validator) — a semi-trusted role reachable by staking and being added to the council via a prior governance vote.
- **Trigger**: The attacker must become a block proposer. Under `WeightedRandom` policy this occurs with probability proportional to stake; under `RoundRobin` it is deterministic.
- **Mechanism**: The attacker runs modified node software that writes the unauthorized vote directly into `header.Vote` during block preparation, bypassing the API check.
- **Scope**: Only exploitable on chains where `PermissionlessCompatibleBlock` is `nil` or not yet reached. Mainnet and Kairos operate in `single` mode; if the Permissionless fork has not been activated, the window is open.
- **No collusion required**: A single malicious council member suffices.

### Recommendation

Remove the `IsPermissionlessForkEnabled` gate from the governing-node check in `VerifyVote`. The restriction should apply in `single` mode regardless of fork status, matching the API-level behavior:

```go
params := h.GetParamSet(blockNum)
if params.GovernanceMode == "single" && vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [7](#0-6) 

### Proof of Concept

1. Deploy a chain with `governance.governancemode = "single"`, `governance.governingnode = A`, and `PermissionlessCompatibleBlock = nil`.
2. Add a second council member `B` (not the governing node).
3. Wait for `B` to become the block proposer (guaranteed under `RoundRobin`).
4. `B` runs modified node software that calls `PushMyVotes` with a vote for `reward.mintingamount = 0`, bypassing the API check.
5. `B`'s block is produced with `header.Vote` encoding the unauthorized vote.
6. `VerifyVote` is called: voter `B` is in council ✓, `B` is the proposer ✓, `IsPermissionlessForkEnabled` is `false` → governing-node check skipped ✓, `checkConsistency` for `RewardMintingAmount` returns `nil` ✓. [8](#0-7) 

7. At the next epoch block, `getExpectedGovernance` collects `B`'s vote and ratifies `reward.mintingamount = 0`.
8. From `(k+1)*epoch` onward, `FinalizeState` mints 0 KAIA per block — all validator and fund rewards drop to zero. [9](#0-8)

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

**File:** kaiax/gov/headergov/impl/header.go (L217-233)
```go
// The blockNum's epoch index must be greater than 0. That is, it must be blockNum >= epoch.
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
