### Title
Wrong address checked in `checkConsistency` for `GovernanceGoverningNode` vote allows setting a non-council governing node, permanently locking governance in single mode — (`File: kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` validates a `governance.governingnode` vote by checking whether the **current** governing node is in the council. It should instead check whether the **proposed new** governing node (the vote value) is in the council. Because the current governing node is almost always in the council (it must be to propose blocks and cast votes), the guard is effectively a no-op, allowing a valid vote to install a governing node address that is not a council member. In `single` governance mode this permanently locks all future governance: only the governing node can vote, but a non-council address can never be the block proposer, so it can never embed a vote in a header.

---

### Finding Description

In `checkConsistency`, the `GovernanceGoverningNode` branch reads:

```go
// kaiax/gov/headergov/impl/header.go  lines 159-178
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
```

`params.GoverningNode` is the **current** governing node, not the address being voted in. The vote value — the **new** governing node — is `vote.Value().(common.Address)` and is never checked against the council.

Contrast this with the `AddValidator`/`RemoveValidator` branch immediately below, which correctly uses `vote.Value()`:

```go
// lines 200-202
if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
    return ErrGovNodeInValSetVoteValue
}
```

Because the current governing node is always in the council (it must be to be the block proposer and embed a vote), `slices.Contains(council, params.GoverningNode)` returns `true` for every valid vote, making the guard a dead letter. Any address — including one that has never been added to the council — can be voted in as the new governing node.

The existing test at `header_test.go` line 81 only votes to set the governing node to `validVoter` (the same address that is already the governing node and already in the council), so it does not exercise the case where the vote value is a non-council address.

---

### Impact Explanation

After the vote is ratified (at the next epoch boundary), `params.GoverningNode` becomes the new address. In `single` mode:

1. Only the governing node may cast governance votes (`VerifyVote` enforces `vote.Voter() == params.GoverningNode` post-Permissionless).
2. A voter must be the block proposer (`author == vote.Voter()`), which requires being in the council.
3. A non-council governing node can never be the proposer, so it can never embed a vote.

Governance is permanently frozen: no parameter (unit price, minting amount, committee size, base-fee bounds, etc.) can ever be changed again. The only recovery path would be a hard fork. This is a governance privilege escalation that corrupts protected chain state.

---

### Likelihood Explanation

The governing node must cast a vote whose value is an address not yet in the council. This can happen:

- **Accidentally**: an operator votes to rotate the governing node to a new address before first adding that address to the council via `governance.addvalidator`.
- **Maliciously**: a compromised governing node key intentionally installs an uncontrollable address.

The Kaia mainnet and Kairos testnet both operate in `single` mode with a single governing node, making this the live production configuration. The epoch on mainnet is 604 800 blocks (~1 week), so the window between the vote being cast and the damage becoming irreversible is up to one week.

---

### Recommendation

Replace `params.GoverningNode` with `vote.Value().(common.Address)` so the check validates the **incoming** governing node:

```go
// kaiax/gov/headergov/impl/header.go  line 175
// Before (wrong):
if slices.Contains(council, params.GoverningNode) {

// After (correct):
if slices.Contains(council, vote.Value().(common.Address)) {
```

This mirrors the pattern already used in the `AddValidator`/`RemoveValidator` branch and matches the intent expressed by `ErrGovNodeNotInValSetList` ("gov node is not found in the valset list").

---

### Proof of Concept

1. Chain is in `single` governance mode; `params.GoverningNode = A`; `A` is in the council.
2. `A` proposes a block and embeds `Vote = ("governance.governingnode", B)` where `B` is **not** in the council.
3. `VerifyVote` calls `checkConsistency`. The branch checks `slices.Contains(council, params.GoverningNode)` → `slices.Contains(council, A)` → `true` → returns `nil`. The vote is accepted.
4. At the next epoch block the vote is ratified; `header.Governance` encodes `{"governance.governingnode": B}`.
5. From the following epoch, `params.GoverningNode = B`. `B` is not in the council, cannot be the proposer, and can never embed a vote.
6. All future `VerifyVote` calls for any governance parameter in `single` mode require `vote.Voter() == B`, but `B` can never be the proposer → no governance vote can ever be included in a block again. Governance is permanently locked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L61-109)
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

**File:** kaiax/gov/headergov/impl/header_test.go (L79-81)
```go
		{desc: "valid deriveshaimpl", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceDeriveShaImpl), uint64(1)), expectedError: nil},
		{desc: "deprecated governancemode", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGovernanceMode), "none"), expectedError: ErrDeprecatedVote},
		{desc: "valid governingnode", vote: headergov.NewVoteData(validVoter, string(gov.GovernanceGoverningNode), validVoter.Hex()), expectedError: nil},
```
