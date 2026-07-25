### Title
Non-Governing Council Member Can Re-Add a Governing-Node-Removed Validator Before Permissionless Fork — (`kaiax/gov/headergov/impl/header.go`, `kaiax/valset/impl/getter_council.go`)

---

### Summary

In `"single"` governance mode before the Permissionless hardfork, `VerifyVote` does not enforce that only the governing node may cast `governance.addvalidator` votes. Any council member who is the block proposer can directly embed an `addvalidator` vote in their block header to re-add a validator the governing node just removed. The removed validator is never tracked, so `applyVote` accepts the re-addition unconditionally, corrupting the council set and undermining the governing node's sole authority.

---

### Finding Description

**Role asymmetry in `VerifyVote` (pre-Permissionless)**

`VerifyVote` in `kaiax/gov/headergov/impl/header.go` gates the governing-node restriction behind an `IsPermissionlessForkEnabled` check:

```go
// In single mode, only the governing node can write header.Vote after Permissionless.
params := h.GetParamSet(blockNum)
if h.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(blockNum)) &&
    params.GovernanceMode == "single" &&
    vote.Voter() != params.GoverningNode {
    return ErrVotePermissionDenied
}
``` [1](#0-0) 

Before Permissionless, the only checks are that the voter is in the council and is the block proposer. Any council member who wins the proposer slot can embed any validator vote — including `governance.addvalidator` — and `VerifyVote` will accept it. The test suite explicitly confirms this:

```go
t.Run("pre-permissionless allows non-governing node", func(t *testing.T) {
    config.PermissionlessCompatibleBlock = nil
    ...
    err = h.VerifyVote(...)
    assert.NoError(t, err)
})
``` [2](#0-1) 

The `Vote` RPC API does enforce the restriction unconditionally:

```go
if gMode == "single" && voter != gp.GoverningNode {
    return "", ErrVotePermissionDenied
}
``` [3](#0-2) 

But a council member controlling their own node can bypass the API entirely and write the vote directly into `header.Vote` before proposing the block. `VerifyVote` is the only on-chain gate, and it does not block this before Permissionless.

**No tracking of removed validators in `applyVote`**

`applyVote` in `kaiax/valset/impl/getter_council.go` applies validator votes immediately and in-place with no memory of prior removals:

```go
switch voteKey {
case gov.AddValidator:
    if !council.Contains(address) {
        council.Add(address)
    }
case gov.RemoveValidator:
    if council.Contains(address) {
        council.Remove(address)
    }
}
``` [4](#0-3) 

The only guard is a membership check — there is no denylist of recently removed addresses. The `checkConsistency` function for `AddValidator`/`RemoveValidator` only checks that the governing node itself is not in the vote value:

```go
case gov.AddValidator, gov.RemoveValidator:
    ...
    if slices.Contains(vote.Value().([]common.Address), params.GoverningNode) {
        return ErrGovNodeInValSetVoteValue
    }
    return nil
``` [5](#0-4) 

A developer-left `TODO` in the API layer acknowledges the gap:

```go
// TODO-kaiax: add removevalidator vote check
``` [6](#0-5) 

**The combined attack path**

The existing test `Test_AddRemove` already demonstrates the mechanics — remove at block 1, re-add at block 3, validator is back at block 4:

```go
{5, map[int]vote{1: {gov.RemoveValidator, 3}, 3: {gov.AddValidator, 3}},
 map[int]expected{..., 2: {[]int{0, 1, 2}}, ..., 4: {[]int{0, 1, 2, 3}}}},
``` [7](#0-6) 

In production, the governing node and the re-adding council member are different parties, making this a cross-role governance override.

---

### Impact Explanation

A non-governing council member who wins the block-proposer slot immediately after the governing node's `removevalidator` vote can re-add the removed validator in the very next block. The corrupted value is the on-chain council set stored by `writeCouncil`:

```go
if applyVote(header, council, governingNode) && write {
    writeCouncil(v.ChainKv, num, council.List())
}
``` [8](#0-7) 

Consequences:
- The removed validator re-enters `Council(N)` and is eligible for `QualifiedValidators`, committee selection, and block proposer rotation — directly affecting consensus participation.
- The governing node's sole authority in `"single"` mode is nullified: any council member can silently reverse a removal decision.
- This is a governance privilege escalation that changes protected chain state (the validator set) without the governing node's consent.

---

### Likelihood Explanation

- Requires the attacker to be the block proposer for one block after the governing node's removal vote. In round-robin or weighted-random proposer selection, the next proposer is known or predictable.
- Only one council member needs to act — no majority collusion required.
- The attacker controls their own node binary and can write `header.Vote` directly, bypassing the API-level restriction.
- The attack is silent: the re-addition looks identical to any legitimate `addvalidator` vote on-chain.
- Applies to any network running pre-Permissionless `"single"` mode (or `"none"` mode, where all council members can vote by design but the same re-add-after-remove gap exists).

---

### Recommendation

1. **Enforce the governing-node restriction unconditionally in `VerifyVote`** — remove the `IsPermissionlessForkEnabled` guard so that `"single"` mode blocks non-governing-node validator votes at all fork heights.

2. **Track removed validators per epoch/term** — maintain a denylist of addresses removed during the current governance period and reject `addvalidator` votes targeting those addresses until the next cohort rotation or explicit governing-node override.

3. **Resolve the open TODO** — implement the missing `removevalidator` vote check noted at `api.go:79` to validate that the target address is actually present in the current council before the vote is queued.

---

### Proof of Concept

Network configuration: `"single"` governance mode, pre-Permissionless hardfork, council = `{GovNode, A, B}`.

1. **Block N** — `GovNode` is the proposer. It calls `governance_vote("governance.removevalidator", B)` via the API. The vote is embedded in `header.Vote`. `VerifyVote` accepts it (GovNode is the governing node). `applyVote` removes `B` from the council at block N+1. Council becomes `{GovNode, A}`.

2. **Block N+1** — `A` is the next proposer (deterministic in round-robin). `A` directly writes `governance.addvalidator(B)` into `header.Vote` on its node, bypassing the API restriction. `VerifyVote` checks: `A` is in council ✓, `A` is the block proposer ✓, `IsPermissionlessForkEnabled` is false so the governing-node check is skipped ✓. `checkConsistency` only verifies `B != GovNode` ✓. Vote is accepted.

3. **Block N+2** — `applyVote` re-adds `B` to the council. Council is restored to `{GovNode, A, B}`. The governing node's removal is silently reversed. `B` resumes participation in committee selection, block proposals, and reward distribution.

The exact corrupted storage value is the council list written by `writeCouncil(v.ChainKv, N+1, ...)` — it contains `B` when it should not. [9](#0-8) [10](#0-9)

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

**File:** kaiax/gov/headergov/impl/api.go (L61-63)
```go
	if gMode == "single" && voter != gp.GoverningNode {
		return "", ErrVotePermissionDenied
	}
```

**File:** kaiax/gov/headergov/impl/api.go (L79-79)
```go
	// TODO-kaiax: add removevalidator vote check
```

**File:** kaiax/valset/impl/getter_council.go (L225-228)
```go
	if applyVote(header, council, governingNode) && write {
		insertValidatorVoteBlockNums(v.ChainKv, num)
		writeCouncil(v.ChainKv, num, council.List())
		v.validatorVoteBlockNumsCache = nil
```

**File:** kaiax/valset/impl/getter_council.go (L236-259)
```go
func applyVote(header *types.Header, council *valset.AddressSet, governingNode common.Address) bool {
	voteKey, addresses, ok := parseValidatorVote(header)
	if !ok {
		return false
	}

	originalSize := council.Len()
	for _, address := range addresses {
		if address == governingNode {
			continue
		}
		switch voteKey {
		case gov.AddValidator:
			if !council.Contains(address) {
				council.Add(address)
			}
		case gov.RemoveValidator:
			if council.Contains(address) {
				council.Remove(address)
			}
		}
	}
	return originalSize != council.Len()
}
```

**File:** kaiax/valset/impl/execution_test.go (L130-130)
```go
		{5, map[int]vote{1: {gov.RemoveValidator, 3}, 3: {gov.AddValidator, 3}}, map[int]expected{0: {[]int{0, 1, 2, 3}}, 1: {[]int{0, 1, 2, 3}}, 2: {[]int{0, 1, 2}}, 3: {[]int{0, 1, 2}}, 4: {[]int{0, 1, 2, 3}}}},
```
