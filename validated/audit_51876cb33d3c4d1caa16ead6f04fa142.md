### Title
One-Step `governance.governingnode` Transfer Permanently Locks Chain Governance in `single` Mode — (`File: kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` validates a `governance.governingnode` vote by checking whether the **current** governing node is in the council — not whether the **proposed new** governing node address is valid or reachable. In `single` governance mode (the mode used by Mainnet and Kairos), the governing node is the sole authority for all future votes. A single erroneous vote ratifying an unreachable address as the new governing node permanently and irrecoverably locks all on-chain governance.

---

### Finding Description

In `checkConsistency`, the `GovernanceGoverningNode` case reads:

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

The guard at line 175 checks `params.GoverningNode` — the **current** governing node — against the council. It never inspects `vote.Value().(common.Address)`, which is the **new** address being proposed. Because the current governing node is always in the council (it is the one proposing the block and casting the vote), this check is a no-op: it always passes.

The `GovernanceGoverningNode` format checker in `kaiax/gov/param.go` only requires the value to be a valid `common.Address` type, with no membership or reachability constraint:

```go
GovernanceGoverningNode: {
    Canonicalizer: addressCanonicalizer,
    FormatChecker: func(cv any) bool {
        _, ok := cv.(common.Address)
        return ok
    },
    ...
    DefaultValue: common.HexToAddress("0x0000000000000000000000000000000000000000"),
},
``` [2](#0-1) 

The vote test suite confirms that `NewVoteData` accepts any syntactically valid address — including the zero address — as a new governing node:

```go
{name: gov.GovernanceGoverningNode, value: "0x0000000000000000000000000000000000000000"},
{name: gov.GovernanceGoverningNode, value: "0x000000000000000000000000000abcd000000000"},
``` [3](#0-2) 

Once the vote is cast and ratified at the next epoch block, `header.Governance` is written with the new governing node address. The `VerifyGov` function only checks that the ratified governance matches the locally computed expected governance — it does not re-validate the new governing node's reachability: [4](#0-3) 

After the epoch boundary, `GetParamSet` returns the new (wrong) governing node as the active authority. In `single` mode, `VerifyVote` then enforces that only this new address may cast votes:

```go
if h.ChainConfig.IsPermissionlessForkEnabled(...) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [5](#0-4) 

Since no one holds the private key for the wrong address, no future vote can ever pass `VerifyVote`. Governance is permanently frozen.

The `Vote` API in `kaiax/gov/headergov/impl/api.go` also enforces the same single-mode restriction at the RPC layer, so even the attempt to correct the mistake is rejected:

```go
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
``` [6](#0-5) 

---

### Impact Explanation

The `governance.governingnode` parameter controls who may cast governance votes in `single` mode. All governance parameters — unit price, minting amount, reward ratio, validator set additions/removals, and the `GovParamContract` address — are exclusively controlled by the governing node in this mode. [7](#0-6) 

If the governing node is changed to an address for which no private key exists:

- No future governance votes can be cast or ratified.
- Validator additions and removals are permanently blocked (the `AddValidator`/`RemoveValidator` path also requires the governing node as voter in single mode).
- The `GovParamContract` address cannot be updated, blocking the contract-based governance path as well.
- The chain is permanently locked in its current governance state with no on-chain recovery mechanism.

This constitutes **governance privilege escalation** that permanently changes protected chain state (the `GoverningNode` stored in `header.Governance` and read by every subsequent `GetParamSet` call).

---

### Likelihood Explanation

The trigger is the current governing node (a semi-trusted, single actor) casting a `governance.governingnode` vote with an incorrect address — whether by operator error (typo), key rotation mistake, or a compromised node operator. On Mainnet and Kairos, the governing node is a single address. The epoch on Mainnet is 604,800 blocks (~1 week), meaning the mistake takes effect one epoch after the vote is cast, with no on-chain mechanism to cancel or override it before ratification. The window to detect and correct the error is limited to the remainder of the current epoch, and correction requires the same (now-wrong) governing node to cast a corrective vote — which is only possible if the mistake is caught before the epoch boundary.

---

### Recommendation

1. **Fix the consistency check**: In `checkConsistency`, replace the check on `params.GoverningNode` (the current node) with a check on `vote.Value().(common.Address)` (the proposed new node). Specifically, verify that the proposed new governing node is a member of the current council:

```go
case gov.GovernanceGoverningNode:
    params := h.GetParamSet(blockNum)
    if params.GovernanceMode != "single" {
        return nil
    }
    newGovNode := vote.Value().(common.Address)  // check the NEW value
    council, err := h.ValSet.GetCouncil(blockNum - 1)
    if err != nil {
        return err
    }
    if slices.Contains(council, newGovNode) {
        return nil
    }
    return ErrGovNodeNotInValSetList
```

2. **Implement a two-step transfer**: Require the proposed new governing node to explicitly accept the role (e.g., by casting a confirmation vote or signing an acceptance transaction) before the change takes effect. This mirrors the `Ownable2Step` pattern and prevents irrecoverable lock-out from a single erroneous vote.

3. **Add a cancellation window**: Allow the current governing node to cancel a pending `governance.governingnode` change within the same epoch before it is ratified.

---

### Proof of Concept

**Setup**: Mainnet or Kairos in `single` governance mode. Current governing node is `0xGovNode` (a valid council member with a known private key).

**Step 1**: The governing node operator calls the `governance_vote` RPC with a typo:
```json
{"method": "governance_vote", "params": ["governance.governingnode", "0xDeAdBeEf000000000000000000000000DeAdBeEf"]}
```

**Step 2**: `Vote()` in `api.go` calls `checkConsistency`. The `GovernanceGoverningNode` case checks `slices.Contains(council, params.GoverningNode)` — i.e., whether the **current** `0xGovNode` is in the council. It is. The check passes. The vote is queued.

**Step 3**: When `0xGovNode` next proposes a block, `PrepareHeader` writes the vote into `header.Vote`. `VerifyVote` on other nodes passes for the same reason.

**Step 4**: At the next epoch block `k*epoch`, `getExpectedGovernance` collects the vote and produces `{"governance.governingnode": "0xDeAdBeEf..."}`. This is written into `header.Governance`. All nodes accept it via `VerifyGov`.

**Step 5**: Starting from block `(k+1)*epoch`, `GetParamSet` returns `GoverningNode = 0xDeAdBeEf...`. Any subsequent call to `Vote()` or `VerifyVote` with any other voter returns `ErrVotePermissionDenied`. No one holds the key for `0xDeAdBeEf...`. Governance is permanently frozen.

**Corrupted state**: `params.GoverningNode` is permanently set to an unreachable address in the persistent `header.Governance` chain history, affecting every future call to `GetParamSet` for all blocks after `(k+1)*epoch`.

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

**File:** kaiax/gov/headergov/vote_test.go (L20-25)
```go
		{name: gov.GovernanceGoverningNode, value: "000000000000000000000000000abcd000000000"},
		{name: gov.GovernanceGoverningNode, value: "0x0000000000000000000000000000000000000000"},
		{name: gov.GovernanceGoverningNode, value: "0x000000000000000000000000000abcd000000000"},
		{name: gov.GovernanceGoverningNode, value: "0xc0cbe1c770fbce1eb7786bfba1ac2115d5c0a456"},
		{name: gov.GovernanceGoverningNode, value: common.HexToAddress("000000000000000000000000000abcd000000000")},
		{name: gov.GovernanceGoverningNode, value: common.HexToAddress("0xc0cbe1c770fbce1eb7786bfba1ac2115d5c0a456")},
```

**File:** kaiax/gov/headergov/impl/api.go (L61-63)
```go
	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/README.md (L44-47)
```markdown
The ratification condition is determined by the `governance.governancemode` parameter. Mainnet and Kairos both operate in `single` mode. There are two governance modes:

- `none` mode: all members of the GC can vote. For each governance parameter, the last vote in the epoch will be ratified.
- `single` mode: only one member of the GC, stipulated in the parameter `governance.governingnode`, can vote. All valid votes from the governing node in the epoch are ratified in block order. For each governance parameter, the last vote in the epoch will be ratified.
```
