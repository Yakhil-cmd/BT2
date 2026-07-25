### Title
Unvalidated Peer-Supplied `StakingInfo` Written to DB During Fast-Sync Corrupts Validator Qualification and Reward Distribution — (`datasync/downloader/queue.go`, `datasync/downloader/downloader.go`)

---

### Summary

During fast-sync, a malicious P2P peer can supply a `P2PStakingInfo` payload with attacker-controlled `CouncilStakingAmounts` and `RewardAddrs` for any pre-Kaia-fork staking-interval block. The delivery validation function is an explicit no-op, so the data is accepted unconditionally and written to the persistent staking DB. After sync completes, `GetStakingInfo` for pre-Kaia blocks reads the DB entry first and returns it without re-deriving from state, causing corrupted staking data to govern validator qualification and block-reward distribution for the affected staking epoch.

---

### Finding Description

**Step 1 — No-op validation at delivery**

`queue.DeliverStakingInfos` contains a `validate` callback that unconditionally returns `nil`:

```go
validate := func(index int, header *types.Header) error {
    // TODO-Kaia-Snapsync update validation logic
    return nil
}
``` [1](#0-0) 

There is no check that `stakingInfoList[index].BlockNum` matches the header's number, and no cross-check against the header's `StateRoot` or any on-chain commitment.

**Step 2 — Unconditional DB write in `commitFastSyncData`**

```go
if result.StakingInfo != nil {
    d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
}
``` [2](#0-1) 

The same pattern repeats in `commitPivotBlock`. [3](#0-2) 

**Step 3 — DB is the authoritative source for pre-Kaia staking info**

`GetStakingInfo` checks the DB first for pre-Kaia blocks and returns immediately on a hit, bypassing state derivation entirely:

```go
if !isKaia {
    if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
        s.stakingInfoCache.Add(sourceNum, si)
        return si, nil   // ← corrupted entry returned here
    }
}
// Read from the state  ← never reached if DB entry exists
``` [4](#0-3) 

**Step 4 — Staking info governs validator qualification and reward addresses**

`GetDemotedValidators` / `GetQualifiedValidators` call `GetStakingInfo` and compare `StakingAmounts` against `MinimumStake` to decide which council members are qualified. [5](#0-4) 

Block reward distribution uses `StakingInfo.RewardAddrs` and `StakingInfo.StakingAmounts` to compute per-validator payouts. [6](#0-5) 

**Step 5 — Staking info is only scheduled for pre-Kaia staking-interval blocks**

`newFetchResult` schedules a staking-info fetch only when `!isKaiaFork` and the block number is a multiple of `stakingUpdateInterval`, confirming the attack surface is exactly the pre-Kaia staking epochs. [7](#0-6) 

---

### Impact Explanation

An attacker who controls a single P2P peer reachable by a fast-syncing node can:

1. **Redirect block rewards** — by substituting `RewardAddrs` with attacker-controlled addresses, all staking-epoch rewards for the affected epoch flow to the attacker after the victim node resumes block processing.
2. **Manipulate validator qualification** — by inflating their own `StakingAmounts` above `MinimumStake` or deflating competitors' amounts below it, the attacker alters `QualifiedValidators`, affecting proposer selection probability and committee composition for every block in the staking epoch.

Both effects persist durably in the DB and are served from cache on subsequent calls, so they survive node restarts.

---

### Likelihood Explanation

- The attacker needs only a single P2P connection to the victim during fast-sync — a permissionless operation.
- The victim must be in `FastSync` mode with `WeightedRandom` proposer policy on a pre-Kaia chain (or syncing historical pre-Kaia epochs).
- No cryptographic break, key compromise, or validator-majority collusion is required.
- The `TODO` comment in the validation function confirms this gap is known but unimplemented.

---

### Recommendation

In `queue.DeliverStakingInfos`, implement the missing validation: verify that `stakingInfoList[index].BlockNum` equals `header.Number.Uint64()`. Additionally, after fast-sync completes, re-derive staking info from the available state trie for each staking-interval block and overwrite any DB entry that differs, or refuse to write DB entries from peers entirely and rely solely on state derivation (as is already done post-Kaia).

---

### Proof of Concept

1. Stand up a two-node network (pre-Kaia fork, `WeightedRandom` policy).
2. Modify the serving node's `handleStakingInfoRequestMsg` to return a `P2PStakingInfo` with inflated `CouncilStakingAmounts` for one validator and a replaced `RewardAddrs` entry pointing to an attacker address.
3. Connect the syncing node in `FastSync` mode to the malicious peer.
4. After sync, call `kaia_getStakingInfo` on the synced node for the affected staking epoch — the corrupted values are returned.
5. Observe that `GetQualifiedValidators` reflects the inflated staking amounts, and that block reward distribution for subsequent blocks in that epoch sends funds to the attacker-controlled reward address.

### Citations

**File:** datasync/downloader/queue.go (L95-98)
```go
	if (fastSync || snapSync) && proposerPolicy == uint64(istanbul.WeightedRandom) &&
		(header.Number.Uint64()%stakingUpdateInterval == 0 && !isKaiaFork) {
		item.pending |= (1 << stakingInfoType)
	}
```

**File:** datasync/downloader/queue.go (L956-958)
```go
	validate := func(index int, header *types.Header) error {
		// TODO-Kaia-Snapsync update validation logic
		return nil
```

**File:** datasync/downloader/downloader.go (L1881-1884)
```go
		if result.StakingInfo != nil {
			d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
			logger.Info("Imported new staking information", "number", result.StakingInfo.BlockNum)
		}
```

**File:** datasync/downloader/downloader.go (L1896-1899)
```go
	if result.StakingInfo != nil {
		d.stakingModule.PutStakingInfoToDB(result.StakingInfo.BlockNum, staking.ToStakingInfo(result.StakingInfo))
		logger.Info("Imported new staking information on pivot block", "number", result.StakingInfo.BlockNum, "pivot", block.Number())
	}
```

**File:** kaiax/staking/impl/getter.go (L57-63)
```go
	// Only before Kaia, try the database
	if !isKaia {
		if si := ReadStakingInfo(s.ChainKv, sourceNum); si != nil {
			s.stakingInfoCache.Add(sourceNum, si)
			return si, nil
		}
	}
```

**File:** kaiax/valset/impl/getter.go (L38-48)
```go
// GetDemotedValidators returns council − qualified at block `num`.
func (v *ValsetModule) GetDemotedValidators(num uint64) ([]common.Address, error) {
	if v.Chain.Config().IsPermissionlessForkEnabled(new(big.Int).SetUint64(num)) {
		return v.getDemoted(num)
	}
	demoted, err := v.getDemotedPermissioned(num)
	if err != nil {
		return nil, err
	}
	return demoted.List(), nil
}
```

**File:** kaiax/reward/impl/getter.go (L334-367)
```go
// getDeferredRewardFullKore is for non-Simple policy and after Kore.
func getDeferredRewardFullKore(config *reward.RewardConfig, execFee, burntFee, blobFee *big.Int, si *staking.StakingInfo) (*reward.RewardSpec, error) {
	var (
		spec             = reward.NewRewardSpec()
		minted           = new(big.Int).Set(config.MintingAmount)
		distributableFee = new(big.Int).Sub(execFee, burntFee)
	)

	// Distribute using RewardRatio first. Unlike Legacy, fees are not distributed here
	// because fees are exclusively allocated to proposer. By the way, remainder goes to KIF.
	validators, kif, kef := config.RewardRatio.Split(minted)
	proposer, stakers := config.Kip82Ratio.Split(validators)
	ratioRemainder := calcRemainder(minted, proposer, stakers, kif, kef)
	kif.Add(kif, ratioRemainder)

	// Further distribute using Kip82Ratio. By the way, remainder goes to proposer.
	// After Prague, if the CLStaking is not nil, the proposer and staking rewards are proportionally distributed to both CN and CL.
	// For proposer rewards, see `specWithProposerAndFunds`.
	stakersAlloc, kip82Remainder := assignStakingRewards(config, stakers, si)
	proposer.Add(proposer, kip82Remainder)
	stakers.Sub(stakers, kip82Remainder)

	// Proposer gets the fees.
	proposer.Add(proposer, distributableFee)

	spec.Minted = minted
	spec.TotalFee = new(big.Int).Add(execFee, blobFee)
	spec.BurntFee = new(big.Int).Add(burntFee, blobFee)
	spec.Stakers = stakers
	for addr, amount := range stakersAlloc {
		spec.IncRecipient(addr, amount)
	}
	spec = specWithProposerAndFunds(spec, config, proposer, kif, kef, si)
	return spec, nil
```
