### Title
Stale Cross-Parameter Consistency Check Allows `LowerBoundBaseFee > UpperBoundBaseFee` via Same-Epoch Concurrent Votes — (`kaiax/gov/headergov/impl/header.go`)

---

### Summary

`checkConsistency` validates each governance vote in isolation against the **current effective** parameter set, never against other votes already pending in the same epoch. In `none` governance mode (the repository default), two GC members — or a single member who proposes two blocks in the same epoch — can cast votes for `kip71.lowerboundbasefee` and `kip71.upperboundbasefee` that each individually pass the cross-parameter guard, but together produce `LowerBoundBaseFee > UpperBoundBaseFee` after epoch ratification. `VerifyGov` at the epoch block does not re-validate cross-parameter consistency of the combined ratified set. The resulting invalid parameter pair permanently corrupts `NextMagmaBlockBaseFee` for every subsequent block, distorting KAIA fee burning and reward distribution.

---

### Finding Description

`checkConsistency` in `kaiax/gov/headergov/impl/header.go` enforces two cross-parameter guards:

```
case gov.Kip71LowerBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads CURRENT effective UpperBound
    if vote.Value().(uint64) > params.UpperBoundBaseFee {
        return ErrLowerBoundBaseFee
    }
case gov.Kip71UpperBoundBaseFee:
    params := h.GetParamSet(blockNum)          // reads CURRENT effective LowerBound
    if vote.Value().(uint64) < params.LowerBoundBaseFee {
        return ErrUpperBoundBaseFee
    }
``` [1](#0-0) 

Each check reads only the **current effective** value of the counterpart parameter via `h.GetParamSet(blockNum)`. It does not inspect other votes already cast in the same epoch. This is the exact analog of the BlueBerry bug: only one component of a coupled pair is "accrued" (checked against the new value), while the other component remains at its stale pre-vote value.

In `none` governance mode — the repository default (`DefaultGovernanceMode = "none"`) — all GC members may vote, and for each parameter the last vote in the epoch is ratified: [2](#0-1) 

A single GC member who is the proposer for two blocks in the same epoch can cast:

1. **Block B1**: vote `kip71.lowerboundbasefee = 500 gwei` → check: `500 ≤ 750` (current upper) ✓  
2. **Block B2**: vote `kip71.upperboundbasefee = 100 gwei` → check: `100 ≥ 25` (current lower) ✓

Both votes pass `checkConsistency` individually. At the epoch boundary, `getExpectedGovernance` collects all votes from the epoch and ratifies them together: [3](#0-2) 

`VerifyGov` only checks that `header.Governance` matches the locally computed governance data — it performs no cross-parameter consistency validation on the combined ratified set: [4](#0-3) 

The invalid parameter pair `{LowerBound: 500 gwei, UpperBound: 100 gwei}` is accepted into the canonical chain and takes effect at the next epoch.

---

### Impact Explanation

After the epoch transition, `NextMagmaBlockBaseFee` in `params/kip71_config.go` clamps `parentBaseFee` against both bounds:

```go
if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
    parentBaseFee = upperBoundBaseFee   // 100 gwei
} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
    parentBaseFee = lowerBoundBaseFee   // 500 gwei
}
``` [5](#0-4) 

With `upper=100 gwei, lower=500 gwei`, any `parentBaseFee ≥ 100 gwei` is clamped to 100 gwei (the first branch fires), and any `parentBaseFee < 100 gwei` is clamped to 500 gwei. The base fee oscillates between two invalid bounds for every subsequent block. Since the deferred fee path burns `F/2` and distributes the rest to proposers, stakers, KIF, and KEF, the incorrect base fee directly corrupts:

- The amount of KAIA burnt per block (unauthorized burn)
- The reward distributed to proposers, stakers, KIF, and KEF (unauthorized reward distribution) [6](#0-5) 

This is a persistent, irrecoverable corruption of the fee mechanism for all blocks after the epoch boundary, affecting system-managed KAIA funds.

---

### Likelihood Explanation

In `none` mode (the default governance mode), any GC member who is the proposer for two blocks in the same epoch can trigger this unilaterally — no coordination between multiple GC members is required. The epoch length on Mainnet is 604,800 blocks (~1 week), giving ample opportunity for a single GC member to be the proposer twice. The attack requires no special privileges beyond being a GC member and proposer, which is a valid semi-trusted trigger.

---

### Recommendation

`checkConsistency` should also inspect pending votes for the counterpart parameter already cast in the current epoch before accepting a new vote. Concretely, when validating a `Kip71LowerBoundBaseFee` vote, retrieve the pending `Kip71UpperBoundBaseFee` vote from `h.groupedVotes` for the current epoch (if any) and use its value instead of the current effective value. Alternatively, `VerifyGov` at the epoch block should validate cross-parameter consistency of the entire ratified parameter set before accepting the governance header.

---

### Proof of Concept

1. Deploy a chain with `governance.governancemode = "none"`, `kip71.lowerboundbasefee = 25 gwei`, `kip71.upperboundbasefee = 750 gwei`.
2. GC member A is the proposer for block 100 in epoch 1. They call `governance_vote("kip71.lowerboundbasefee", 500000000000)`. `checkConsistency` checks `500 ≤ 750` ✓ — vote accepted.
3. GC member B is the proposer for block 200 in epoch 1. They call `governance_vote("kip71.upperboundbasefee", 100000000000)`. `checkConsistency` checks `100 ≥ 25` ✓ — vote accepted.
4. At block 604800 (epoch boundary), `getExpectedGovernance` collects both votes. `VerifyGov` accepts the governance header encoding `{kip71.lowerboundbasefee: 500 gwei, kip71.upperboundbasefee: 100 gwei}` — no cross-parameter check is performed.
5. From block 604801 onwards, `NextMagmaBlockBaseFee` produces incorrect base fees (oscillating between 100 gwei and 500 gwei), permanently corrupting KAIA fee burning and reward distribution for every subsequent block.

### Citations

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

**File:** kaiax/gov/headergov/impl/header.go (L179-192)
```go
	case gov.Kip71LowerBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) > params.UpperBoundBaseFee {
			return ErrLowerBoundBaseFee
		} else {
			return nil
		}
	case gov.Kip71UpperBoundBaseFee:
		params := h.GetParamSet(blockNum)
		if vote.Value().(uint64) < params.LowerBoundBaseFee {
			return ErrUpperBoundBaseFee
		} else {
			return nil
		}
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

**File:** params/governance_params.go (L40-40)
```go
	DefaultGovernanceMode            = "none"
```

**File:** params/kip71_config.go (L80-86)
```go
	// check the case of upper/lowerBoundBaseFee is updated by governance mechanism
	parentBaseFee := parentHeaderBaseFee
	if parentBaseFee.Cmp(upperBoundBaseFee) >= 0 {
		parentBaseFee = upperBoundBaseFee
	} else if parentBaseFee.Cmp(lowerBoundBaseFee) <= 0 {
		parentBaseFee = lowerBoundBaseFee
	}
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
