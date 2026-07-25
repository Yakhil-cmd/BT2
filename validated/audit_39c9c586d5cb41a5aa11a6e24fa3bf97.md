### Title
Zero-Address Governing Node Vote Permanently Locks Single-Mode Governance - (`kaiax/gov/param.go`, `kaiax/gov/headergov/impl/header.go`)

### Summary

The `FormatChecker` for the `governance.governingnode` parameter accepts `0x0000000000000000000000000000000000000000` as a valid vote value. Once ratified in "single" governance mode, the governing node becomes the zero address, and all subsequent vote attempts are permanently rejected because no validator can ever have address(0). Governance is irreversibly locked.

### Finding Description

The `GovernanceGoverningNode` parameter's `FormatChecker` only verifies that the canonicalized value is a `common.Address` type — it does not reject the zero address: [1](#0-0) 

The test suite explicitly confirms that `"0x0000000000000000000000000000000000000000"` is treated as a valid vote value for `governance.governingnode`: [2](#0-1) 

The `checkConsistency` function for a `GovernanceGoverningNode` vote validates only that the **current** `params.GoverningNode` is in the council — it never validates the **proposed new value**: [3](#0-2) 

After the zero-address vote is ratified, `VerifyVote` permanently rejects all future votes in single mode because no validator can have address(0): [4](#0-3) 

The `Vote` API enforces the same check, so no node can even queue a corrective vote: [5](#0-4) 

### Impact Explanation

Once `GoverningNode` is set to `0x0000...0000` and the epoch boundary passes, the effective `ParamSet` permanently carries a zero governing node. Every subsequent call to `VerifyVote` (consensus path) and `Vote` (API path) rejects all votes with `ErrVotePermissionDenied`. No governance parameter — reward minting amount, gas price, validator set additions/removals, or any other — can ever be changed again. The chain continues to produce blocks but governance is permanently frozen.

### Likelihood Explanation

The trigger requires the current governing node (a single semi-trusted entity on mainnet/Kairos) to cast a vote for `governance.governingnode = 0x0`. This could occur by operator error (e.g., passing an empty address string that canonicalizes to zero) or deliberately. The governing node is not a fully privileged actor — it is expected to be able to change governance parameters but not to permanently destroy the governance mechanism itself. The system provides no guard against this irreversible action.

### Recommendation

Add a non-zero address check to the `FormatChecker` for `GovernanceGoverningNode` in `kaiax/gov/param.go`:

```go
GovernanceGoverningNode: {
    Canonicalizer: addressCanonicalizer,
    FormatChecker: func(cv any) bool {
        addr, ok := cv.(common.Address)
        if !ok {
            return false
        }
        return addr != (common.Address{}) // reject zero address
    },
    ...
},
```

Additionally, `checkConsistency` in `kaiax/gov/headergov/impl/header.go` should validate that the **proposed new governing node value** is a non-zero address that exists in the current council, not just that the current governing node is in the council.

### Proof of Concept

1. Chain is running in `governance.governancemode = "single"` with `governance.governingnode = 0xGovNode` (a real validator address).
2. The governing node calls `governance_vote("governance.governingnode", "0x0000000000000000000000000000000000000000")`.
3. `NewVoteData` succeeds — `addressCanonicalizer` converts the string to `common.Address{}`, and `FormatChecker` returns `true` because `_, ok := cv.(common.Address)` passes for the zero address. [6](#0-5) 
4. `checkConsistency` passes — it checks `slices.Contains(council, params.GoverningNode)` where `params.GoverningNode` is the **current** (non-zero) governing node, which is in the council. [7](#0-6) 
5. The vote is inscribed in `header.Vote` when the governing node proposes a block, and ratified at the next epoch boundary into `header.Governance`.
6. From `(k+1)*epoch` onwards, `GetParamSet(N).GoverningNode == common.Address{}`.
7. Every call to `VerifyVote` with `IsPermissionlessForkEnabled && GovernanceMode == "single"` returns `ErrVotePermissionDenied` for all validators, since `vote.Voter() != common.Address{}` is always true. [8](#0-7) 
8. Governance is permanently locked. No corrective vote can be submitted or accepted.

### Citations

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

**File:** kaiax/gov/headergov/vote_test.go (L20-21)
```go
		{name: gov.GovernanceGoverningNode, value: "000000000000000000000000000abcd000000000"},
		{name: gov.GovernanceGoverningNode, value: "0x0000000000000000000000000000000000000000"},
```

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

**File:** kaiax/gov/headergov/impl/api.go (L61-63)
```go
	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```
