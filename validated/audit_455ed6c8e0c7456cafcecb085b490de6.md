### Title
Wrong Address Checked in `GovernanceGoverningNode` Consistency Validation Allows Setting Governing Node to Non-Council Address, Permanently Locking Governance - (File: `kaiax/gov/headergov/impl/header.go`)

---

### Summary

In `checkConsistency`, the `GovernanceGoverningNode` case validates the **current** governing node against the council instead of the **proposed new** governing node. This means the consistency guard is a no-op: it always passes when the current governing node is in the council (which is always true, since the voter must be the governing node and must be in the council). As a result, the governing node can ratify a vote that sets `governance.governingnode` to any arbitrary address — including one not in the validator council — permanently locking on-chain governance.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` handles the `GovernanceGoverningNode` vote case as follows:

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

The intent of this check — as evidenced by the error name `ErrGovNodeNotInValSetList` and the analogous `AddValidator`/`RemoveValidator` case which correctly uses `vote.Value()` — is to ensure the **new** governing node address is a member of the validator council. However, the code checks `params.GoverningNode` (the **current** governing node) instead of `vote.Value().(common.Address)` (the **proposed new** governing node).

For comparison, the `AddValidator`/`RemoveValidator` case correctly references `vote.Value()`:

```go
case gov.AddValidator, gov.RemoveValidator:
    ...
    if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
        return ErrGovNodeInValSetVoteValue
    }
``` [2](#0-1) 

The `GovernanceGoverningNode` vote value is canonicalized to a `common.Address` by `addressCanonicalizer`: [3](#0-2) 

Because `VerifyVote` already enforces that the voter is in the council and is the governing node (in single mode after Permissionless), `params.GoverningNode` is **always** in the council when `checkConsistency` is reached. The check therefore always returns `nil` — it is a dead guard. [4](#0-3) 

---

### Impact Explanation

Once the vote is ratified at the next epoch block, `governance.governingnode` is permanently set to an address that is not in the validator council. In `single` mode:

- Only the governing node may cast votes (`ErrVotePermissionDenied` is returned for all others).
- The governing node must also be the block proposer, and proposers are drawn exclusively from the council.
- A non-council address can never be a block proposer.

Therefore, no valid governance vote can ever be cast again. All governance parameters — including `governance.unitprice`, reward ratios, minting amounts, committee size, and validator set changes — are permanently frozen at their current values. The chain's governance module is irreversibly bricked.

The corrupted protected state value is `governance.governingnode` stored in `header.Governance` at the epoch block, which propagates into the persistent `govHistory` and `GetParamSet` output used by every subsequent block.

---

### Likelihood Explanation

The trigger requires the current governing node (a semi-trusted privileged actor in single mode) to call `governance_vote("governance.governingnode", "<non-council-address>")`. The broken consistency check passes silently. The vote is ratified at the next epoch boundary (up to 604,800 blocks / ~1 week on Mainnet). No other guard exists to reject the ratified value. This could occur through operator error, key compromise, or malicious intent.

---

### Recommendation

Replace `params.GoverningNode` with `vote.Value().(common.Address)` in the `GovernanceGoverningNode` consistency check:

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
    // Check the PROPOSED new governing node, not the current one
    if slices.Contains(council, vote.Value().(common.Address)) {
        return nil
    }
    return ErrGovNodeNotInValSetList
```

This ensures that a `governance.governingnode` vote can only be ratified if the proposed new governing node is already a member of the validator council, preserving the invariant that the governing node can always propose blocks and cast votes.

---

### Proof of Concept

**Setup:** Single-mode governance. Council = `[A, B, C]`. Current governing node = `A`. `X` is an arbitrary address not in the council.

1. Node `A` (governing node, block proposer) calls:
   ```
   governance_vote("governance.governingnode", "0x<X>")
   ```
2. `checkConsistency` is called with `vote.Name() == GovernanceGoverningNode` and `vote.Value() == X`.
3. The check evaluates `slices.Contains(council, params.GoverningNode)` → `slices.Contains([A,B,C], A)` → `true` → returns `nil`. The vote passes.
4. At the next epoch block, `header.Governance` is written with `{"governance.governingnode": X}`.
5. `VerifyGov` accepts it (it only checks that the governance matches the locally derived expected value, which also uses the broken `checkConsistency`).
6. From `(k+1)*epoch` onward, `GetParamSet` returns `GoverningNode = X`.
7. Any attempt to cast a vote now hits: `vote.Voter() != params.GoverningNode` → `ErrVotePermissionDenied` for all council members including `A`.
8. `X` is not in the council, so it can never be a block proposer, and can never embed a vote in a block header.
9. Governance is permanently locked. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** kaiax/gov/headergov/impl/header.go (L87-107)
```go
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

**File:** kaiax/gov/param.go (L231-244)
```go
	GovernanceGoverningNode: {
		Canonicalizer: addressCanonicalizer,
		FormatChecker: func(cv any) bool {
			_, ok := cv.(common.Address)
			return ok
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Governance == nil {
				return nil, errors.New("governance is not set")
			}
			return c.Governance.GoverningNode, nil
		},
		DefaultValue: common.HexToAddress("0x0000000000000000000000000000000000000000"),
	},
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
