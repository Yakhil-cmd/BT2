### Title
Unauthenticated P2P Peer Can Inject Arbitrary StakingInfo During Recovery, Corrupting Persisted Validator/Reward State — (`datasync/downloader/downloader.go`)

### Summary

`DeliverStakingInfos` forwards staking data from **any** connected P2P peer into the recovery channel (`stakingInfoRecoveryCh`) without verifying that the delivering peer is the one designated by `SyncStakingInfo`. A malicious peer that sends a `StakingInfoMsg` with correctly-guessed block numbers during an active recovery window will have its fabricated `NodeIds`, `RewardAddrs`, and `StakingAmounts` written permanently to the staking DB.

### Finding Description

`SyncStakingInfo` designates a single trusted peer (`conn`) and opens `stakingInfoRecoveryCh`: [1](#0-0) 

The recovery goroutine reads from that channel and unconditionally persists whatever arrives: [2](#0-1) 

The only guard is a block-number equality check (line 673). There is **no peer-ID check**.

`DeliverStakingInfos` is called for every peer that sends a `StakingInfoMsg`: [3](#0-2) 

Inside `DeliverStakingInfos`, the `id` parameter is used only for the normal sync path; for the recovery path it is silently ignored: [4](#0-3) 

Any registered P2P peer can therefore race the legitimate peer and push crafted data into `stakingInfoRecoveryCh`. Because the channel is buffered with capacity 1, a message that arrives before the legitimate peer's response fills the slot and is consumed first.

### Impact Explanation

`PutStakingInfoToDB` permanently overwrites the staking record for the targeted block number with attacker-supplied `NodeIds`, `RewardAddrs`, and `StakingAmounts`. These fields drive:

- **Validator-set selection** (weighted-random proposer policy reads `NodeIds` / `StakingAmounts`)
- **Block reward distribution** (reward module reads `RewardAddrs` / `StakingAmounts`)

Corrupted records persist across restarts and affect every future epoch that references those block numbers, constituting durable loss of correct reward distribution and potentially invalid validator-set composition.

### Likelihood Explanation

- Any node that has established a P2P connection qualifies as a "registered peer."
- The target block numbers are deterministic (multiples of `StakingUpdateInterval`, default 86400) and are also directly readable via the public `SyncStakingInfoStatus()` API.
- The 30-second recovery window per batch gives an attacker ample time to send a crafted `StakingInfoMsg`.
- No cryptographic material or privileged key is required.

### Recommendation

Inside `DeliverStakingInfos`, gate the recovery-channel write on a peer-ID match against the designated recovery peer. Store the recovery peer ID alongside the channel:

```go
// In SyncStakingInfo, store the peer ID:
d.stakingInfoRecoveryPeerID = id
d.stakingInfoRecoveryCh = make(chan []*staking.P2PStakingInfo, 1)

// In DeliverStakingInfos:
func (d *Downloader) DeliverStakingInfos(id string, stakingInfos []*staking.P2PStakingInfo) error {
    if d.isStakingInfoRecovery && id == d.stakingInfoRecoveryPeerID {
        d.stakingInfoRecoveryCh <- stakingInfos
    }
    return d.deliver(id, d.stakingInfoCh, &stakingInfoPack{id, stakingInfos}, ...)
}
```

### Proof of Concept

1. Start a node with `WeightedRandom` proposer policy and two connected peers A and B.
2. Delete staking DB entries for block N (a staking-update-interval block).
3. Operator calls `SyncStakingInfo(peerA_id, N, N)` — recovery starts, `isStakingInfoRecovery = true`, request sent to peer A.
4. Before peer A responds, peer B sends a `StakingInfoMsg` containing a `P2PStakingInfo` with `BlockNum = N` and fabricated `NodeIds`/`RewardAddrs`/`StakingAmounts`.
5. `handleStakingInfoMsg` → `DeliverStakingInfos(peerB_id, ...)` → `stakingInfoRecoveryCh <- fabricatedData` (no peer-ID check).
6. Recovery goroutine reads peer B's data, block-number check passes, calls `PutStakingInfoToDB(N, fabricatedStakingInfo)`.
7. Assert that the DB now contains peer B's fabricated `NodeIds`/`RewardAddrs`/`StakingAmounts` for block N.

### Citations

**File:** datasync/downloader/downloader.go (L633-641)
```go
	conn := d.peers.Peer(id)
	if conn == nil {
		d.isStakingInfoRecovery = false
		return errors.New("the given peer is not registered")
	}

	d.stakingInfoRecoveryBlocks = blockNums
	d.stakingInfoRecoveryTotal = len(blockNums)
	d.stakingInfoRecoveryCh = make(chan []*staking.P2PStakingInfo, 1)
```

**File:** datasync/downloader/downloader.go (L670-679)
```go
			case stakingInfos := <-d.stakingInfoRecoveryCh:
				logger.Info("received stakinginfos", "len", len(stakingInfos))
				for _, stakingInfo := range stakingInfos {
					if d.stakingInfoRecoveryBlocks[0] != stakingInfo.BlockNum {
						logger.Error("failed to receive expected block", "expected", d.stakingInfoRecoveryBlocks[0], "actual", stakingInfo.BlockNum)
						return
					}
					d.stakingModule.PutStakingInfoToDB(stakingInfo.BlockNum, staking.ToStakingInfo(stakingInfo))
					fixed++
					d.stakingInfoRecoveryBlocks = d.stakingInfoRecoveryBlocks[1:]
```

**File:** datasync/downloader/downloader.go (L1936-1941)
```go
func (d *Downloader) DeliverStakingInfos(id string, stakingInfos []*staking.P2PStakingInfo) error {
	if d.isStakingInfoRecovery {
		d.stakingInfoRecoveryCh <- stakingInfos
	}
	return d.deliver(id, d.stakingInfoCh, &stakingInfoPack{id, stakingInfos}, stakingInfoInMeter, stakingInfoDropMeter)
}
```

**File:** node/cn/handler.go (L1199-1213)
```go
func handleStakingInfoMsg(pm *ProtocolManager, p Peer, msg p2p.Msg) error {
	if pm.chainconfig.Istanbul == nil || pm.chainconfig.Istanbul.ProposerPolicy != uint64(istanbul.WeightedRandom) {
		return errResp(ErrUnsupportedEnginePolicy, "the engine is not istanbul or the policy is not weighted random")
	}

	// A batch of stakingInfos arrived to one of our previous requests
	var stakingInfos []*staking.P2PStakingInfo
	if err := msg.Decode(&stakingInfos); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// Deliver all to the downloader
	if err := pm.downloader.DeliverStakingInfos(p.GetID(), stakingInfos); err != nil {
		logger.Debug("Failed to deliver staking information", "err", err)
	}
	return nil
```
