The attack premise requires careful tracing. Let me map the exact code paths.

**`expectedBlockHash` source — `HandleIstanbulPreprepare`, not `HandleVRankPreprepare`:** [1](#0-0) 

`AddPrepreparedTime` is called from `HandleIstanbulPreprepare` using the real consensus block's hash. The VRankPreprepare handler never calls `AddPrepreparedTime`.

**`HandleVRankPreprepare` — candidates sign and echo whatever hash is in the message:** [2](#0-1) 

After verifying the proposer's signature (which covers `blockNum || round || block.Hash()`), the candidate signs a `VRankCandidate` with `BlockHash: block.Hash()` — the hash from the VRankPreprepare, not from the Istanbul Preprepare.

**`HandleVRankCandidate` — no block-hash validation at receipt time:** [3](#0-2) 

Only ECDSA and BLS signatures are verified. The `BlockHash` field is stored as-is.

**`EvaluateCandidates` — hash comparison happens here:** [4](#0-3) 

`expectedBlockHash` comes from the collector (set by `HandleIstanbulPreprepare` with the real hash). Any candidate whose `VRankCandidate.BlockHash != expectedBlockHash` is added to `cfReport`.

**`VerifyHeader` — accepts any cfReport whose addresses are valid candidates:** [5](#0-4) 

`validateNonEpochVRank` only checks membership, sort order, and deduplication — it does not verify that the reported candidates actually failed.

---

**Attack trace:**

1. Malicious proposer sends Istanbul Preprepare with real block hash `H_real` → committee members set `expectedBlockHash = H_real` in collector.
2. Same proposer sends VRankPreprepare with tampered hash `H_fake ≠ H_real`, signed with their legitimate key → `verifyVRankPreprepareSender` passes.
3. Candidates receive the tampered VRankPreprepare, verify the valid proposer signature, and broadcast `VRankCandidate{BlockHash: H_fake}`.
4. Committee members store these candidates without hash validation.
5. `EvaluateCandidates(N-1, round)` compares `H_fake != H_real` for every candidate → all candidates added to `cfReport`.
6. Proposer of block N encodes this maximal cfReport into `header.VRank`.
7. `VerifyHeader` accepts it — all addresses are valid candidates, sorted, deduplicated.
8. CFS scores for the entire candidate set are incremented by every honest proposer in the epoch who reads this committed cfReport.

The attack requires only one malicious proposer (not majority collusion), uses no cryptographic breaks, and is reachable via the P2P message path. The fraudulent cfReport is indistinguishable from a legitimate one at verification time.

---

### Title
Malicious Proposer Can Inject Maximal cfReport via Tampered VRankPreprepare Block Hash — (`kaiax/vrank/impl/handler.go`, `kaiax/vrank/impl/getter.go`)

### Summary
A legitimate proposer can send a `VRankPreprepare` whose embedded block hash differs from the actual Istanbul Preprepare block hash. Candidates echo that tampered hash in their `VRankCandidate` responses. Because `EvaluateCandidates` compares candidate hashes against the real `expectedBlockHash` (set from the Istanbul Preprepare), every candidate appears to have sent a wrong hash, producing a maximal cfReport. `VerifyHeader` accepts this report, permanently inflating CFS scores for all candidates.

### Finding Description
`HandleIstanbulPreprepare` sets `expectedBlockHash` in the collector from the real consensus block: [6](#0-5) 

`HandleVRankPreprepare` verifies only that the sender is the legitimate proposer — it does not check that `msg.Block.Hash()` matches the canonical block at that height: [7](#0-6) 

Candidates then sign and broadcast a `VRankCandidate` carrying the tampered hash verbatim: [8](#0-7) 

`HandleVRankCandidate` stores the message without any block-hash check: [9](#0-8) 

`EvaluateCandidates` then marks every candidate as failed because `H_fake != H_real`: [10](#0-9) 

`VerifyHeader` accepts the resulting maximal cfReport because it only validates membership, sort order, and deduplication: [5](#0-4) 

### Impact Explanation
CFS scores for all candidates are permanently incremented in the committed chain state. Over an epoch, repeated attacks by the same or different proposers can drive every candidate's CFS above any threshold, corrupting validator selection in the permissionless system. This constitutes durable corruption of protected chain state (validator scoring) without any cryptographic break or majority collusion.

### Likelihood Explanation
Any node that wins a single proposer slot can execute this attack. No special access beyond being the legitimate proposer for one round is required. The attack is silent — honest validators cannot distinguish a fraudulent maximal cfReport from a legitimate one at `VerifyHeader` time.

### Recommendation
In `HandleVRankPreprepare`, reject any `VRankPreprepare` whose `msg.Block.Hash()` does not match the canonical block hash at `msg.Block.NumberU64()` as known to the local chain. Alternatively, derive `expectedBlockHash` from the committed canonical block rather than from the VRankPreprepare or Istanbul Preprepare message, so that `EvaluateCandidates` always compares against the finalized block hash regardless of what hash the proposer advertised.

### Proof of Concept
```
1. Start a test network with permissionless fork enabled.
2. Identify the proposer P for block N at round 0.
3. P sends Istanbul Preprepare with real block B (hash H_real).
4. P sends VRankPreprepare{Block: B', View: V, Sig: Sign(N, 0, H_fake)} where H_fake = H_real XOR 1.
5. All candidates receive the tampered VRankPreprepare, verify P's valid signature, and broadcast VRankCandidate{BlockHash: H_fake}.
6. Committee members store these candidates.
7. Proposer of block N+1 calls EvaluateCandidates(N, 0) → all candidates returned as failed.
8. Assert header(N+1).VRank decodes to the full candidate set.
9. Assert GetCFS(N+1) shows elevated scores for all candidates.
```

### Citations

**File:** kaiax/vrank/impl/handler.go (L44-54)
```go
	// ideally isCommitteeMember(blockNum + 1, round), but committee is not finalized during `blockNum` consensus, thus (blockNum, round).
	if v.isCommitteeMember(blockNum, view.Round.Uint64()) {
		copiedView := bft.View{
			Sequence: new(big.Int).Set(view.Sequence),
			Round:    new(big.Int).Set(view.Round),
		}
		v.prepreparedViewMu.Lock()
		v.prepreparedView = copiedView
		v.prepreparedViewMu.Unlock()
		v.collector.AddPrepreparedTime(vrank.ViewKey{N: blockNum, R: uint8(view.Round.Uint64())}, prepreparedAt, block.Hash())
	}
```

**File:** kaiax/vrank/impl/handler.go (L76-110)
```go
		sender, err := v.recoverVRankPreprepareSender(msg)
		if err != nil {
			return err
		}
		if err := v.verifyVRankPreprepareSender(msg, sender); err != nil {
			return err
		}
		v.pruneSeenPreprepare(block.NumberU64())
		if exactReplay, conflictingView := v.markSeenPreprepare(vrank.ViewKey{N: block.NumberU64(), R: uint8(view.Round.Uint64())}, block.Hash()); exactReplay {
			// ignore seen preprepare
			return nil
		} else if conflictingView {
			logger.Warn("Conflicting VRankPreprepare ignored", "blockNum", block.NumberU64(), "round", view.Round.Uint64(), "blockHash", block.Hash().Hex())
			return nil
		}

		sigHash := v.vrankCandidateSigHash(block.NumberU64(), uint8(view.Round.Uint64()), block.Hash())
		sig, err := crypto.Sign(sigHash.Bytes(), v.NodeKey)
		if err != nil {
			logger.Error("Sign failed", "blockNum", block.NumberU64(), "blockHash", block.Hash().Hex())
			return err
		}
		blsSig := bls.Sign(v.BlsKey, sigHash.Bytes()).Marshal()
		// TODO-Permissionless: Testing only. Remove before production release.
		if v.skipCandidate.Load() {
			logger.Warn("SkipCandidate is enabled, skipping VRankCandidate broadcast")
			return nil
		}
		v.BroadcastVRankCandidate(&vrank.VRankCandidate{
			BlockNumber: block.NumberU64(),
			Round:       uint8(view.Round.Uint64()),
			BlockHash:   block.Hash(),
			Sig:         sig,
			BlsSig:      blsSig,
		})
```

**File:** kaiax/vrank/impl/handler.go (L116-162)
```go
func (v *VRankModule) HandleVRankCandidate(msg *vrank.VRankCandidate) error {
	if !v.ChainConfig.IsPermissionlessForkEnabled(new(big.Int).SetUint64(msg.BlockNumber)) {
		return nil
	}

	receivedAt := time.Now()
	v.prepreparedViewMu.RLock()
	prepreparedSeqNum, prepreparedRound := uint64(0), uint64(0)
	hasPrepreparedView := v.prepreparedView.Sequence != nil && v.prepreparedView.Round != nil
	if hasPrepreparedView {
		prepreparedSeqNum = v.prepreparedView.Sequence.Uint64()
		prepreparedRound = v.prepreparedView.Round.Uint64()
	}
	v.prepreparedViewMu.RUnlock()
	if !hasPrepreparedView {
		return vrank.ErrPrepreparedViewNotSet
	}
	if msg.BlockNumber > prepreparedSeqNum+maxWindow {
		return vrank.ErrTooFar
	}
	if msg.Round > maxRound {
		return vrank.ErrRoundOutOfRange
	}
	if isStaleVRankCandidate(msg, prepreparedSeqNum, prepreparedRound) {
		return nil
	}

	sigHash := v.vrankCandidateSigHash(msg.BlockNumber, msg.Round, msg.BlockHash)
	sender, err := v.recoverVRankCandidateSender(sigHash, msg.Sig)
	if err != nil {
		return err
	}
	blsNum := big.NewInt(0).Add(v.Chain.CurrentHeader().Number, big.NewInt(1)) // head + 1
	blsPub, err := v.Randao.GetBlsPubkey(sender, blsNum)
	if err != nil {
		return fmt.Errorf("%w: %v", vrank.ErrInvalidCandidateBlsSig, err)
	}
	ok, err := bls.VerifySignature(msg.BlsSig, sigHash, blsPub)
	if err != nil || !ok {
		return vrank.ErrInvalidCandidateBlsSig
	}
	vk := vrank.ViewKey{N: msg.BlockNumber, R: msg.Round}
	if v.collector.HasCandMsg(vk, sender) {
		return nil
	}
	v.collector.AddCandMsg(vk, sender, receivedAt, msg)
	return nil
```

**File:** kaiax/vrank/impl/getter.go (L116-139)
```go
	prepreparedAt, expectedBlockHash, viewMap := v.collector.GetViewData(vk)
	if prepreparedAt.IsZero() {
		// No preprepare data — either this node was not a validator for blockNum,
		// or it missed the PREPREPARE message. Either way, nothing to report.
		return []common.Address{}, nil
	}
	candidates, err := v.Valset.GetCandTesting(blockNum)
	if err != nil {
		logger.Error("GetCandTesting failed", "blockNum", blockNum, "err", err)
		return nil, vrank.ErrGetCandidateFailed
	}
	if len(candidates) == 0 {
		return []common.Address{}, nil
	}
	var cfReport []common.Address
	for _, addr := range candidates {
		msgWithTime, arrived := viewMap[addr]
		if !arrived ||
			msgWithTime.Msg == nil ||
			msgWithTime.Msg.BlockHash != expectedBlockHash ||
			msgWithTime.ReceivedAt.Sub(prepreparedAt).Milliseconds() > candidateMsgTimeoutMs {
			cfReport = append(cfReport, addr)
		}
	}
```

**File:** kaiax/vrank/impl/consensus.go (L148-158)
```go
func validateNonEpochVRank(report, candidates []common.Address) error {
	if isNonCandContained(report, candidates) {
		return vrank.ErrInvalidVRankCandidate
	}
	if !isSorted(report) {
		return vrank.ErrVRankNotSorted
	}
	if hasDuplicate(report) {
		return vrank.ErrDuplicateVRankCandidate
	}
	return nil
```
