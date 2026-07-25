### Title
`GovernanceGoverningNode` vote accepts zero address, permanently locking single-mode governance — (File: `kaiax/gov/param.go`)

---

### Summary

The `FormatChecker` for the `GovernanceGoverningNode` parameter in `kaiax/gov/param.go` does not reject `address(0)` as a valid vote value. In "single" governance mode the governing node is the sole entity authorized to cast header-governance votes. If the governing node accidentally submits a vote setting itself to the zero address, and that vote is committed on-chain, governance is permanently frozen: no further votes can ever be cast because no one controls `0x0000…0000`.

---

### Finding Description

**Root cause — missing zero-address guard in `FormatChecker`**

`kaiax/gov/param.go` defines the validation rules for every governance parameter. For `GovernanceGoverningNode` the `FormatChecker` only asserts that the value is a `common.Address`; it does not reject the zero address: [1](#0-0) 

The `DefaultValue` is explicitly `0x0000…0000`, which signals that zero is treated as a legal value throughout the system.

**No downstream guard in `checkConsistency`**

`kaiax/gov/headergov/impl/header.go` performs the only state-level consistency check for a `GovernanceGoverningNode` vote. It verifies that the *current* governing node is in the validator set, but it never inspects the *new* vote value: [2](#0-1) 

A vote whose value is `0x0000…0000` passes this check unconditionally (when `GovernanceMode == "single"` and the current governing node is in the council).

**Confirmed by the test suite**

The unit test for `NewVoteData` explicitly lists a zero-address governing-node vote in the *good* votes table, confirming the path is reachable and accepted: [3](#0-2) 

---

### Impact Explanation

In "single" governance mode only the governing node may embed a vote in a block header. Once a committed vote advances the `GoverningNode` parameter to `0x0000…0000`:

1. The on-chain `GoverningNode` becomes the zero address.
2. No real account controls `0x0000…0000`.
3. No further governance votes can ever be cast.
4. All governance-controlled parameters — reward minting amount, reward ratio, KIF/KEF/KPF splits, committee size, `GovParamContract` pointer — are permanently frozen at their last values.
5. There is no recovery path: the only way to change `GoverningNode` is via a governance vote, which now requires the zero address as the signer.

This is the direct Kaia analog of the original bug: the privileged role (governing node ↔ minter) is the only entity that can update the role address, and setting it to zero permanently destroys that capability.

---

### Likelihood Explanation

The trigger requires the governing node to include a vote with value `0x0000…0000` in a proposed block. Realistic paths:

- A bug or misconfiguration in the operator's voting tooling passes an uninitialized/empty address.
- A scripted governance operation uses a zero-initialized variable before it is populated.
- An operator tests the vote API against a staging address that was never set.

The probability is low but non-zero; the consequence is irreversible and chain-wide.

---

### Recommendation

Add a non-zero guard to the `FormatChecker` for `GovernanceGoverningNode` in `kaiax/gov/param.go`:

```go
GovernanceGoverningNode: {
    Canonicalizer: addressCanonicalizer,
    FormatChecker: func(cv any) bool {
        v, ok := cv.(common.Address)
        return ok && v != (common.Address{})   // reject zero address
    },
    ...
},
```

Optionally, add a parallel guard in `checkConsistency` (`kaiax/gov/headergov/impl/header.go`) to reject any `GovernanceGoverningNode` vote whose value is the zero address, providing defence-in-depth.

---

### Proof of Concept

1. Start a Kaia network with genesis `GovernanceMode = "single"` and `GoverningNode = <validatorAddr>`.
2. From the governing node, construct and broadcast a header-governance vote:
   ```
   governance.governingnode = 0x0000000000000000000000000000000000000000
   ```
3. `NewVoteData` accepts the value (confirmed by the test at line 21 of `vote_test.go`).
4. `VerifyVote` / `checkConsistency` passes: the current governing node is in the council, and the new value is never inspected.
5. After the next epoch boundary the effective `GoverningNode` becomes `0x0000…0000`.
6. Attempt any subsequent governance vote — it is rejected because the signer is not the (now-zero) governing node.
7. Governance is permanently locked; no parameter can ever be updated again.

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

**File:** kaiax/gov/headergov/vote_test.go (L20-25)
```go
		{name: gov.GovernanceGoverningNode, value: "000000000000000000000000000abcd000000000"},
		{name: gov.GovernanceGoverningNode, value: "0x0000000000000000000000000000000000000000"},
		{name: gov.GovernanceGoverningNode, value: "0x000000000000000000000000000abcd000000000"},
		{name: gov.GovernanceGoverningNode, value: "0xc0cbe1c770fbce1eb7786bfba1ac2115d5c0a456"},
		{name: gov.GovernanceGoverningNode, value: common.HexToAddress("000000000000000000000000000abcd000000000")},
		{name: gov.GovernanceGoverningNode, value: common.HexToAddress("0xc0cbe1c770fbce1eb7786bfba1ac2115d5c0a456")},
```
