I need to trace the full attack path through the code carefully before rendering a verdict.

### Title
Malicious Proposer Poisons Candidate's `seenPreprepare` with a Crafted Block Hash, Causing Permanent CFS Failure — (`kaiax/vrank/impl/handler.go`)

---

### Summary

A Byzantine proposer can send a signed `VRankPreprepare` carrying a crafted `wrongHash` to a candidate before the legitimate `IstanbulPreprepare` arrives. Because `HandleVRankPreprepare` only checks that the signer is the current proposer — not that the block hash matches the actual proposed block — the candidate accepts the crafted message, stores `wrongHash` in `seenPreprepare`, and broadcasts a `VRankCandidate` committing to `wrongHash`. When the legitimate `VRankPreprepare` (with `actualBlockHash`) subsequently arrives, `markSeenPreprepare` detects a conflicting view and silently drops it. Every honest validator then evaluates the candidate's `VRankCandidate.BlockHash != expectedBlockHash` and records a CFS failure. The Byzantine filter provides no protection because all honest reporters independently reach the same conclusion.

---

### Finding Description

**Step 1 — Attacker crafts a signed `VRankPreprepare` with `wrongHash`.**

The attacker is the legitimate proposer for `(blockNum, round)` and holds their own private key. They construct a `VRankPreprepare` whose embedded block has a different hash from the actual proposed block, then sign it:

```
sigHash = vrankPreprepareSigHash(blockNum, round, wrongHash)
sig     = Sign(sigHash, attackerKey)
``` [1](#0-0) 

**Step 2 — Candidate's signature check passes.**

`recoverVRankPreprepareSender` recovers the attacker's address from the signature over `wrongHash`. `verifyVRankPreprepareSender` confirms that recovered address equals `GetProposer(blockNum, round)` — which it does, because the attacker IS the proposer. There is no check that `msg.Block.Hash()` matches the block the proposer actually submitted to consensus. [2](#0-1) 

**Step 3 — `markSeenPreprepare` stores `wrongHash`; candidate broadcasts `VRankCandidate` with `wrongHash`.**

`markSeenPreprepare` returns `(false, false)` for the first message, so execution continues. The candidate signs and broadcasts a `VRankCandidate` whose `BlockHash` field is `wrongHash`. [3](#0-2) 

**Step 4 — Legitimate `VRankPreprepare` is permanently dropped.**

When the legitimate `VRankPreprepare` (with `actualBlockHash`) arrives, `markSeenPreprepare` finds `seenPreprepare[vk] == wrongHash != actualBlockHash` and returns `(false, true)`. The message is silently discarded; the candidate never sends a `VRankCandidate` with the correct hash. [4](#0-3) 

**Step 5 — All honest validators mark the candidate as failed.**

Every committee member called `HandleIstanbulPreprepare` with the real block, so their collector stores `expectedBlockHash = actualBlockHash` via `AddPrepreparedTime`. When `EvaluateCandidates` runs, it checks:

```go
msgWithTime.Msg.BlockHash != expectedBlockHash   // wrongHash != actualBlockHash → true
```

and appends the candidate to `cfReport`. [5](#0-4) [6](#0-5) 

**Step 6 — Byzantine filter provides no protection.**

`generateCFSFromCPMatrix` discards the top `F = ProposerCount()/3` per-reporter scores. But in this attack every honest proposer independently reports the candidate as failed (because they all observed `wrongHash != actualBlockHash`). The filter is designed to discard a minority of lying reporters; here all reporters tell the truth about what they observed, so nothing is discarded. [7](#0-6) 

---

### Impact Explanation

A single Byzantine proposer can, on every round they are selected, force one or more honest candidates to accumulate a CFS failure. Over an epoch this degrades the targeted candidates' validator ranking and reduces their future block-proposal probability and reward share. The impact is a persistent, attacker-controlled distortion of reward distribution affecting KAIA staking rewards — within the "reward distribution" impact gate.

---

### Likelihood Explanation

Any validator who is legitimately selected as proposer for a round can execute this attack with no additional privileges, no key compromise, and no collusion. In a permissionless validator set the attacker simply waits for their scheduled proposer slot. The attack requires only the ability to send a P2P `VRankPreprepare` message slightly ahead of the normal `IstanbulPreprepare` broadcast, which is trivially achievable by the proposer itself.

---

### Recommendation

Inside `HandleVRankPreprepare`, after verifying the proposer signature, cross-check `msg.Block.Hash()` against the block hash the local node already knows from `HandleIstanbulPreprepare` (stored in the collector via `AddPrepreparedTime`). If the local node has already recorded `expectedBlockHash` for `ViewKey{N, R}` and `msg.Block.Hash() != expectedBlockHash`, reject the message before updating `seenPreprepare`. This ensures a Byzantine proposer cannot poison the deduplication map with a hash that differs from the actual proposed block.

Alternatively, record the `expectedBlockHash` in `seenPreprepare` only after `HandleIstanbulPreprepare` has run (i.e., only accept a `VRankPreprepare` whose block hash matches the already-known `expectedBlockHash`), so that a crafted early message is rejected rather than stored.

---

### Proof of Concept

```
Setup:
  - Nodes: proposer (P), candidate (C), validator (V)
  - P is GetProposer(1, 0); C is GetCandTesting(1); V is GetCommittee(1, 0)

1. P crafts altBlock with ParentHash=0x01 (different from block1), so altBlock.Hash() != block1.Hash()
2. P signs VRankPreprepare{Block: altBlock, View: view1_0} with P's key → pppBad
3. P sends pppBad to C  (before IstanbulPreprepare)
4. C.HandleVRankPreprepare(pppBad):
     - verifyVRankPreprepareSender passes (P is proposer)
     - markSeenPreprepare stores altBlock.Hash()
     - C broadcasts VRankCandidate{BlockHash: altBlock.Hash()} to V
5. V.HandleIstanbulPreprepare(block1, view1_0):
     - collector.AddPrepreparedTime(vk, now, block1.Hash())  ← expectedBlockHash = block1.Hash()
6. P sends legitimate VRankPreprepare{Block: block1} to C
7. C.HandleVRankPreprepare(pppGood):
     - markSeenPreprepare returns (false, true) → DROPPED
8. V.HandleVRankCandidate(msg with BlockHash=altBlock.Hash()):
     - stored in collector
9. V.EvaluateCandidates(1, 0):
     - msg.BlockHash (altBlock.Hash()) != expectedBlockHash (block1.Hash()) → C added to cfReport

Assert: cfReport contains C  ← honest candidate falsely marked as failed
```

This is directly analogous to the existing test `"same view with different block hash must not rebroadcast VRankCandidate"` in `handler_test.go` (lines 369–393), which already confirms that the second message is dropped — but does not assert the downstream `EvaluateCandidates` consequence. [8](#0-7)

### Citations

**File:** kaiax/vrank/impl/handler.go (L84-110)
```go
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

**File:** kaiax/vrank/impl/handler.go (L190-202)
```go
func (v *VRankModule) markSeenPreprepare(vk vrank.ViewKey, blockHash common.Hash) (bool, bool) {
	v.seenPreprepareMu.Lock()
	defer v.seenPreprepareMu.Unlock()

	if seenHash, ok := v.seenPreprepare[vk]; ok {
		if seenHash == blockHash {
			return true, false
		}
		return false, true
	}
	v.seenPreprepare[vk] = blockHash
	return false, false
}
```

**File:** kaiax/vrank/impl/handler.go (L218-226)
```go
func (v *VRankModule) recoverVRankPreprepareSender(msg *vrank.VRankPreprepare) (common.Address, error) {
	sigHash := v.vrankPreprepareSigHash(msg.Block.NumberU64(), uint8(msg.View.Round.Uint64()), msg.Block.Hash())
	pubkey, err := crypto.SigToPub(sigHash.Bytes(), msg.Sig)
	if err != nil {
		logger.Debug("SigToPub failed for VRankPreprepare", "err", err, "blockNum", msg.Block.NumberU64())
		return common.Address{}, fmt.Errorf("%w: %v", vrank.ErrInvalidProposerSig, err)
	}
	return crypto.PubkeyToAddress(*pubkey), nil
}
```

**File:** kaiax/vrank/impl/handler.go (L228-241)
```go
func (v *VRankModule) verifyVRankPreprepareSender(msg *vrank.VRankPreprepare, sender common.Address) error {
	blockNum := msg.Block.NumberU64()
	round := msg.View.Round.Uint64()
	proposer, err := v.Valset.GetProposer(blockNum, round)
	if err != nil {
		logger.Debug("GetProposer failed", "err", err, "blockNum", blockNum)
		return err
	}
	if sender != proposer {
		logger.Debug("VRankPreprepare from non-proposer", "sender", sender.Hex(), "proposer", proposer.Hex(), "blockNum", blockNum)
		return vrank.ErrMsgFromNonProposer
	}
	return nil
}
```

**File:** kaiax/vrank/impl/getter.go (L131-138)
```go
	for _, addr := range candidates {
		msgWithTime, arrived := viewMap[addr]
		if !arrived ||
			msgWithTime.Msg == nil ||
			msgWithTime.Msg.BlockHash != expectedBlockHash ||
			msgWithTime.ReceivedAt.Sub(prepreparedAt).Milliseconds() > candidateMsgTimeoutMs {
			cfReport = append(cfReport, addr)
		}
```

**File:** kaiax/vrank/collector.go (L96-101)
```go
func (c *Collector) AddPrepreparedTime(vk ViewKey, prepreparedAt time.Time, expectedBlockHash common.Hash) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prepreparedMap[vk] = prepreparedAt
	c.blockHashMap[vk] = expectedBlockHash
}
```

**File:** kaiax/vrank/impl/scoring.go (L199-227)
```go
func generateCFSFromCPMatrix(cpMatrix vrank.CPMatrix) map[common.Address]uint64 {
	F := cpMatrix.ProposerCount() / 3
	return byzantineFilter(cpMatrix, F)
}

// byzantineFilter computes CFS scores from pre-aggregated per-candidate failure data.
//
// cpMatrix[candidate][reporter] is the number of times reporter included candidate
// in cfReport over the epoch. F is the number of highest reporter totals to discard
// per candidate, defending against up to F byzantine reporters that may inflate scores.
func byzantineFilter(cpMatrix vrank.CPMatrix, F int) map[common.Address]uint64 {
	cfs := make(map[common.Address]uint64)
	for cand, reporterToScore := range cpMatrix {
		scores := slices.Collect(maps.Values(reporterToScore))
		slices.Sort(scores)
		if F >= len(scores) {
			// since `scores` contain non-zero scores only, F >= len(scores) can happen, in which case all scores are discarded.
			scores = nil
		} else {
			scores = scores[:len(scores)-F]
		}
		var sum uint64
		for _, t := range scores {
			sum += t
		}
		cfs[cand] = sum
	}
	return cfs
}
```

**File:** kaiax/vrank/impl/handler_test.go (L369-393)
```go
	t.Run("same view with different block hash must not rebroadcast VRankCandidate", func(t *testing.T) {
		cns, valset, _ := newCNMulti(t, 3)
		proposer, candidate, validator := cns[0], cns[1], cns[2]

		altBlock := types.NewBlockWithHeader(&types.Header{
			Number:     big.NewInt(1),
			ParentHash: common.HexToHash("0x01"),
		})

		valset.EXPECT().GetCandTesting(uint64(1)).Return([]common.Address{candidate.Addr}, nil).AnyTimes()
		valset.EXPECT().GetProposer(uint64(1), uint64(0)).Return(proposer.Addr, nil).AnyTimes()
		valset.EXPECT().GetCommittee(uint64(1), uint64(0)).Return([]common.Address{validator.Addr}, nil).Times(1)

		pppSig1 := signVRankPreprepare(t, proposer.VRankModule, proposer.Key, block1.NumberU64(), 0, block1.Hash())
		pppMsg1 := &vrank.VRankPreprepare{Block: block1, View: view1_0, Sig: pppSig1}
		pppSig2 := signVRankPreprepare(t, proposer.VRankModule, proposer.Key, altBlock.NumberU64(), 0, altBlock.Hash())
		pppMsg2 := &vrank.VRankPreprepare{Block: altBlock, View: view1_0, Sig: pppSig2}

		require.NoError(t, candidate.VRankModule.HandleVRankPreprepare(pppMsg1))
		req := mustPop(t, candidate.sub)
		assert.Equal(t, []common.Address{validator.Addr}, req.Targets)

		require.NoError(t, candidate.VRankModule.HandleVRankPreprepare(pppMsg2))
		mustNotPop(t, candidate.sub)
	})
```
