### Title
Double-Counting of Consolidated Staking Amount When Multiple NodeIds Sharing a RewardAddr Are Both in the Council — (File: `kaiax/valset/impl/getter_demote.go`)

---

### Summary

`collectStakingAmounts` assigns the **full consolidated staking amount** (the sum of all staking amounts for every NodeId sharing a RewardAddr) to **each** council member that belongs to that consolidated group. If two NodeIds from the same consolidated group are both admitted to the council via a governance vote, each receives the full consolidated amount, inflating their apparent stake and allowing under-staked validators to bypass the minimum-staking demotion requirement.

---

### Finding Description

`StakingInfo.consolidateNodes()` legitimately aggregates multiple NodeIds that share a single `RewardAddr` into one `consolidatedNode` whose `StakingAmount` is the sum of all individual stakes:

```
CN1 = {NodeIds:[N1,N2], RewardAddr:R1, StakingAmount:A1+A2}
``` [1](#0-0) 

`collectStakingAmounts` then iterates over every `cn.NodeIds` and, for each NodeId that is present in the council, writes `cn.StakingAmount` (the consolidated total) into the result map:

```go
for _, cn := range cns {
    for _, node := range cn.NodeIds {
        if _, ok := stakingAmounts[node]; ok {
            stakingAmounts[node] = float64(cn.StakingAmount) // ← full consolidated amount
        }
    }
}
``` [2](#0-1) 

The function's own comment acknowledges the hidden assumption:

> "Note: This function assumes that validator registration is controlled, and that only one NodeId per reward address can be part of the validator set. If this assumption changes, this logic may need to be revisited." [3](#0-2) 

In the **permissioned mode**, the council is managed via header governance votes. The `applyVote` function only guards against duplicate *addresses*; it does **not** check whether the new address shares a `RewardAddr` with an existing council member:

```go
case gov.AddValidator:
    if !council.Contains(address) {
        council.Add(address)   // ← no RewardAddr uniqueness check
    }
``` [4](#0-3) 

A validator that becomes a block proposer can therefore vote to add a second NodeId (`N2`) from the same consolidated group (same `RewardAddr R1`) to the council. Once both `N1` and `N2` are in the council, `collectStakingAmounts` produces:

```
stakingAmounts[N1] = A1 + A2   (should be A1)
stakingAmounts[N2] = A1 + A2   (should be A2)
```

`getDemotedValidatorsIstanbul` then compares each node's apparent stake against `minStake`:

```go
for _, node := range council.List() {
    if uint64(stakingAmounts[node]) < minStake {
        demoted.Add(node)
    }
}
``` [5](#0-4) 

If `A1 < minStake` and `A2 < minStake` but `A1+A2 >= minStake`, both `N1` and `N2` pass the check and remain **qualified** — neither is demoted — even though neither individually meets the staking requirement.

---

### Impact Explanation

- **Validator demotion bypass**: Validators whose individual staking contracts hold less than `reward.minstake` remain in the qualified set and are eligible to be selected as committee members and proposers.
- **Consensus integrity**: Under-staked validators participate in block production and BFT voting, violating the protocol's security assumption that only sufficiently-staked validators influence consensus.
- **Exact corrupted value**: `stakingAmounts[N2]` is set to `A1+A2` instead of `A2`, inflating the apparent stake of `N2` by `A1`.

---

### Likelihood Explanation

The trigger requires two conditions that can both be satisfied by a semi-trusted actor:

1. **AddressBook has multiple NodeIds with the same RewardAddr** — this is an explicitly supported and documented configuration (the entire `consolidateNodes` mechanism exists to handle it).
2. **A validator (proposer) casts a governance vote to add the second NodeId to the council** — in `governance.governancemode = "none"`, any validator that wins a proposer slot can include such a vote in the block header.

No external-service compromise, majority-validator collusion, or operator-only action is required beyond what a single semi-trusted validator can do unilaterally.

---

### Recommendation

**Option A — Enforce RewardAddr uniqueness in `applyVote`**: Before adding a new address to the council, check whether any existing council member shares the same `RewardAddr` in the current `StakingInfo`. Reject the vote if a collision is found.

**Option B — Fix `collectStakingAmounts` to avoid double-assignment**: Instead of assigning the consolidated amount to every matching NodeId, assign it only to the *first* matching NodeId found in the council, and assign zero (or the individual amount) to the rest. This preserves the demotion semantics even when the uniqueness assumption is violated.

**Option C — Add an explicit guard in `getDemotedValidatorsIstanbul`**: After calling `collectStakingAmounts`, detect and log any case where two council members share a consolidated group, and treat the excess members as demoted.

---

### Proof of Concept

**Setup (permissioned WeightedRandom chain, post-Istanbul hardfork):**

```
AddressBook:
  NodeId=N1, StakingContract=S1, RewardAddr=R1, StakingAmount=A1  (A1 < minStake)
  NodeId=N2, StakingContract=S2, RewardAddr=R1, StakingAmount=A2  (A2 < minStake, A1+A2 >= minStake)

Initial council: [N1, N3, N4, ...]   (N2 not yet in council)
```

**Step 1 — Normal state (no exploit):**

`collectStakingAmounts([N1, N3, N4, ...], si)` returns `{N1: A1+A2, N3: A3, N4: A4, ...}`.  
`N1` appears qualified because `A1+A2 >= minStake`. This is already inflated but N2 is not yet in the council.

**Step 2 — Attacker (validator N1 becomes proposer) casts vote:**

Block header includes `Vote = AddValidator(N2)`.  
`applyVote` checks `!council.Contains(N2)` → true → adds N2.  
New council: `[N1, N2, N3, N4, ...]`.

**Step 3 — Double-counting triggered:**

`collectStakingAmounts([N1, N2, N3, N4, ...], si)`:
- CN1 = {NodeIds:[N1,N2], StakingAmount:A1+A2}
- Inner loop hits N1 → `stakingAmounts[N1] = A1+A2`
- Inner loop hits N2 → `stakingAmounts[N2] = A1+A2`

`getDemotedValidatorsIstanbul`:
- `stakingAmounts[N1] = A1+A2 >= minStake` → N1 not demoted ✓ (inflated but same result)
- `stakingAmounts[N2] = A1+A2 >= minStake` → **N2 not demoted** ✗ (should be demoted: A2 < minStake)

**Result:** N2 is now a qualified validator eligible for committee selection and block proposals, despite holding only `A2 < minStake` in its staking contract. The minimum-staking invariant is broken.

### Citations

**File:** kaiax/staking/staking_info.go (L124-148)
```go
func (si *StakingInfo) consolidateNodes() *[]consolidatedNode {
	// because Go map is not ordered, rList keeps track of the occurrence order of RewardAddrs.
	// to later arrange the consolidatedNodes.
	cmap := make(map[common.Address]*consolidatedNode)
	rList := make([]common.Address, 0, len(si.RewardAddrs))
	nToR := make(map[common.Address]common.Address)

	for i, n := range si.NodeIds {
		r := si.RewardAddrs[i]
		// Unique nodeId is guaranteed by AddressBook.
		nToR[n] = r
		if cn, ok := cmap[r]; ok {
			cn.NodeIds = append(cn.NodeIds, n)
			cn.StakingContracts = append(cn.StakingContracts, si.StakingContracts[i])
			cn.StakingAmount += si.StakingAmounts[i]
		} else {
			cmap[r] = &consolidatedNode{
				NodeIds:          []common.Address{n},
				StakingContracts: []common.Address{si.StakingContracts[i]},
				RewardAddr:       r,
				StakingAmount:    si.StakingAmounts[i],
			}
			rList = append(rList, r)
		}
	}
```

**File:** kaiax/valset/impl/getter_demote.go (L87-92)
```go
	// First filter by staking amounts.
	for _, node := range council.List() {
		if uint64(stakingAmounts[node]) < minStake {
			demoted.Add(node)
		}
	}
```

**File:** kaiax/valset/impl/getter_demote.go (L122-124)
```go
// Note: This function assumes that validator registration is controlled,
// and that only one NodeId per reward address can be part of the validator set.
// If this assumption changes, this logic may need to be revisited.
```

**File:** kaiax/valset/impl/getter_demote.go (L125-138)
```go
func collectStakingAmounts(nodes []common.Address, si *staking.StakingInfo) map[common.Address]float64 {
	cns := si.ConsolidatedNodes()
	stakingAmounts := make(map[common.Address]float64, len(nodes))
	for _, node := range nodes {
		stakingAmounts[node] = 0
	}
	for _, cn := range cns {
		for _, node := range cn.NodeIds {
			if _, ok := stakingAmounts[node]; ok {
				stakingAmounts[node] = float64(cn.StakingAmount)
			}
		}
	}
	return stakingAmounts
```

**File:** kaiax/valset/impl/getter_council.go (L247-256)
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
```
