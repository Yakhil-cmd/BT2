### Title
Governance Permanently Locked via Unvalidated `governingnode` Vote Value in `none` Mode — (File: `kaiax/gov/headergov/impl/header.go`)

---

### Summary

In `governance.governancemode = "none"`, any council member can cast a valid vote to set `governance.governingnode` to an arbitrary address that is **not** in the council. If a subsequent vote in the same epoch changes the mode to `"single"`, the new governing node (not a council member) can never propose blocks, and the `"single"`-mode restriction permanently bars every other council member from voting. Governance is irreversibly locked — an exact analog of the RUSD.sol "restrictions set to NONE cannot be renewed" pattern.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` handles a `governance.governingnode` vote as follows:

```go
case gov.GovernanceGoverningNode:
    params := h.GetParamSet(blockNum)
    if params.GovernanceMode != "single" {
        return nil          // ← no validation at all in "none" mode
    }
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    if slices.Contains(council, params.GoverningNode) {
        return nil          // ← checks CURRENT node, not the vote VALUE
    }
    return ErrGovNodeNotInValSetList
``` [1](#0-0) 

Two defects are present simultaneously:

1. **In `"none"` mode the entire check is skipped** (`return nil` at line 163–165). Any council member who is the block proposer can vote to set `governance.governingnode` to any address — including one that is not in the council and can therefore never propose a block.

2. **Even in `"single"` mode the check validates the *current* governing node (`params.GoverningNode`), not the *new* value carried by the vote.** The new address is never verified to be a council member.

After the Permissionless fork, `VerifyVote` enforces:

```go
if h.ChainConfig.IsPermissionlessForkEnabled(...) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [2](#0-1) 

Once the governing node is set to a non-council address and the mode is `"single"`, this guard permanently blocks every council member from voting, because the only permitted voter (the governing node) is not in the council and can never be a block proposer.

`governance.governancemode` itself has no consistency guard — it is in the catch-all `return nil` branch:

```go
case gov.GovernanceDeriveShaImpl, gov.GovernanceGovParamContract, gov.GovernanceGovernanceMode, ...
    return nil
``` [3](#0-2) 

The `GovernanceGovernanceMode` parameter accepts both `"none"` and `"single"`:

```go
if v == "none" || v == "single" {
    return true
}
``` [4](#0-3) 

---

### Impact Explanation

After the attack is ratified:

- `governance.governingnode` points to an address outside the council.
- `governance.governancemode` is `"single"`.
- The governing node can never be a block proposer (not in council), so it can never embed a `header.Vote`.
- Every other council member is rejected by `ErrVotePermissionDenied`.
- **No governance parameter can ever be updated again**: `reward.mintingamount`, `reward.ratio`, `governance.unitprice`, `reward.minimumstake`, `istanbul.committeesize`, etc. are all frozen at their current values permanently.

This is a governance privilege escalation that permanently corrupts protected chain state (the governance parameter update path), matching the allowed impact gate.

---

### Likelihood Explanation

- The chain must be in `"none"` mode (the default for non-Mainnet deployments; Mainnet starts in `"single"` but the code does not enforce immutability).
- A **single** malicious council member is sufficient — no majority collusion required.
- The attacker needs to be the last proposer in the epoch for both the `governance.governingnode` and `governance.governancemode` parameters (so their votes are the ones ratified). This is achievable by timing proposals near the epoch boundary.
- No special privilege beyond being a council member is required.

---

### Recommendation

In `checkConsistency`, validate the **vote value** (the proposed new governing node) against the council, not just the current governing node, and apply this check regardless of the current governance mode:

```go
case gov.GovernanceGoverningNode:
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    if err != nil {
        return err
    }
    newGovNode := vote.Value().(common.Address)
    if !slices.Contains(council, newGovNode) {
        return ErrGovNodeNotInValSetList
    }
    return nil
```

Additionally, consider adding a cross-parameter consistency check that rejects a `governance.governancemode = "single"` vote if the current `governance.governingnode` is not in the council.

---

### Proof of Concept

Precondition: chain is post-Permissionless fork, `governance.governancemode = "none"`.

1. Malicious council member **M** (a valid block proposer) calls `governance_vote("governance.governingnode", X)` where `X` is an address not in the council.
2. When M is next selected as proposer, the vote is embedded in `header.Vote`. `VerifyVote` passes (M is in council; `checkConsistency` returns `nil` because mode is `"none"`). The vote is recorded.
3. M calls `governance_vote("governance.governancemode", "single")`.
4. When M is next selected as proposer (still within the same epoch), this vote is embedded. Both votes are ratified at the epoch boundary and take effect at the start of the next epoch.
5. From that epoch onward: `GovernanceMode = "single"`, `GoverningNode = X` (not in council).
6. Any council member attempting to vote hits `ErrVotePermissionDenied` (they are not `X`).
7. `X` is never selected as proposer (not in council), so it can never embed a vote.
8. **Governance is permanently frozen.** All mutable parameters — minting amount, reward ratio, unit price, minimum stake, committee size — are locked at their current values with no on-chain recovery path.

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

**File:** kaiax/gov/headergov/impl/header.go (L157-178)
```go
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

**File:** kaiax/gov/param.go (L218-221)
```go
			if v == "none" || v == "single" {
				return true
			}
			return false
```
