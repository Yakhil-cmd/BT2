### Title
Round Truncation in `markSeenPreprepare` Allows Malicious Proposer to Poison Candidate `seenPreprepare` State and Suppress CFS Reporting — (`kaiax/vrank/impl/handler.go`)

---

### Summary

`HandleVRankPreprepare` passes the full `uint64` round to `verifyVRankPreprepareSender` / `GetProposer`, but truncates it to `uint8` when keying `seenPreprepare`. Because `HandleVRankPreprepare` has **no upper-bound check on the incoming round** (unlike `HandleVRankCandidate`, which guards with `if msg.Round > maxRound`), a malicious proposer can craft a VRankPreprepare with `round = 256` (or any multiple of 256 that satisfies the modulo condition), pass proposer verification, and poison `seenPreprepare[{N, 0}]` with a wrong block hash — causing the legitimate round-0 preprepare to be silently dropped as a "conflicting view" on every candidate node, suppressing their VRankCandidate broadcasts and corrupting their CFS scores and KAIA reward entitlements.

---

### Finding Description

**The truncation mismatch:**

In `HandleVRankPreprepare`, the view round is used in three places:

1. **Signature recovery** — `vrankPreprepareSigHash` receives `uint8(msg.View.Round.Uint64())`: [1](#0-0) 

2. **Proposer verification** — `verifyVRankPreprepareSender` uses the raw `uint64` round: [2](#0-1) 

3. **Deduplication key** — `markSeenPreprepare` uses `uint8(view.Round.Uint64())`: [3](#0-2) 

When `round = 256`, `uint8(256) = 0`. So the sig hash is computed with round=0, the proposer is looked up with round=256, and the dedup key is `{N, 0}`.

**No round guard in `HandleVRankPreprepare`:**

`HandleVRankCandidate` explicitly rejects out-of-range rounds: [4](#0-3) 

`HandleVRankPreprepare` has no equivalent check. `MaxRound = 10` is defined: [5](#0-4) 

but is never applied to the incoming VRankPreprepare round.

**The `seenPreprepare` conflict path:**

`markSeenPreprepare` returns `conflictingView = true` when the same `ViewKey` is already stored with a different hash, causing the message to be silently dropped: [6](#0-5) 

---

### Impact Explanation

A malicious proposer (proposer for round 0 at block N) crafts a VRankPreprepare with `round = 256` and a **different** block hash (e.g., `common.Hash{0xff...}`). They send this to all candidates before the legitimate round-0 preprepare.

On each candidate node:
- `recoverVRankPreprepareSender`: sig hash uses `uint8(256)=0` — the attacker signs with the round-0 sig hash, so recovery succeeds.
- `verifyVRankPreprepareSender`: calls `GetProposer(N, 256)`. Since `GetProposer` wraps modulo committee size, and 256 is divisible by common committee sizes (4, 8, 16, 32, 64, 128, 256), this returns the same address as `GetProposer(N, 0)` — the attacker. Verification passes.
- `markSeenPreprepare({N, 0}, maliciousHash)`: stores the wrong hash under key `{N, 0}`.

When the legitimate round-0 preprepare arrives:
- `markSeenPreprepare({N, 0}, realHash)`: finds `maliciousHash ≠ realHash` → returns `conflictingView = true`. [7](#0-6) 

The candidate silently drops the legitimate preprepare and never broadcasts `VRankCandidate`. Validators receive no candidate responses for block N, so the CPMatrix entry `cpMatrix[candidate][proposer]` is never incremented. The candidate's CFS score is suppressed, directly reducing their KAIA reward entitlement computed at epoch boundaries. [8](#0-7) 

---

### Likelihood Explanation

- Requires the attacker to be a **single malicious validator** who is the proposer for round 0 at block N — not majority collusion.
- Requires committee size to divide 256 (e.g., 4, 8, 16, 32, 64, 128, 256) — common in practice.
- The malicious VRankPreprepare must arrive at candidates **before** the legitimate one — achievable via network timing since the attacker controls when they send both messages.
- The attack is repeatable every block where the attacker is proposer.

---

### Recommendation

1. **Add a round bound check in `HandleVRankPreprepare`**, mirroring the guard in `HandleVRankCandidate`:
   ```go
   if view.Round.Uint64() > uint64(maxRound) {
       return vrank.ErrRoundOutOfRange
   }
   ```
   This prevents any round ≥ 256 from reaching `markSeenPreprepare`.

2. **Use consistent round types throughout `HandleVRankPreprepare`**: extract `round := uint8(view.Round.Uint64())` once after the bound check and use it for sig hash, proposer lookup, and the seenPreprepare key — eliminating the split between `uint64` and `uint8` representations.

---

### Proof of Concept

```
Setup:
  - Committee size = 4; validators V0..V3; candidates C0..C3
  - Block N, round 0: proposer = V0 (attacker)
  - GetProposer(N, 256) = GetProposer(N, 256 % 4) = GetProposer(N, 0) = V0

Attack:
  1. V0 crafts VRankPreprepare{Block: blockN, View: {Seq: N, Round: 256}, Sig: Sign(vrankPreprepareSigHash(N, 0, 0xff...), V0.key)}
  2. V0 sends this to all candidates C0..C3 before the legitimate preprepare.
  3. Each Ci processes it:
     - recoverVRankPreprepareSender: sigHash uses uint8(256)=0 → recovers V0 ✓
     - verifyVRankPreprepareSender: GetProposer(N, 256) = V0 ✓
     - markSeenPreprepare({N, 0}, 0xff...) → stored
  4. V0 sends legitimate VRankPreprepare{Block: blockN, View: {Seq: N, Round: 0}, Sig: ...}
  5. Each Ci: markSeenPreprepare({N, 0}, realHash) → conflictingView=true → dropped
  6. No VRankCandidate is broadcast by any Ci for block N.
  7. Validators record zero candidate responses for block N → CFS scores for C0..C3 are suppressed → reduced KAIA rewards at epoch end.
```

### Citations

**File:** kaiax/vrank/impl/handler.go (L84-84)
```go
		if exactReplay, conflictingView := v.markSeenPreprepare(vrank.ViewKey{N: block.NumberU64(), R: uint8(view.Round.Uint64())}, block.Hash()); exactReplay {
```

**File:** kaiax/vrank/impl/handler.go (L86-90)
```go
			return nil
		} else if conflictingView {
			logger.Warn("Conflicting VRankPreprepare ignored", "blockNum", block.NumberU64(), "round", view.Round.Uint64(), "blockHash", block.Hash().Hex())
			return nil
		}
```

**File:** kaiax/vrank/impl/handler.go (L136-138)
```go
	if msg.Round > maxRound {
		return vrank.ErrRoundOutOfRange
	}
```

**File:** kaiax/vrank/impl/handler.go (L194-201)
```go
	if seenHash, ok := v.seenPreprepare[vk]; ok {
		if seenHash == blockHash {
			return true, false
		}
		return false, true
	}
	v.seenPreprepare[vk] = blockHash
	return false, false
```

**File:** kaiax/vrank/impl/handler.go (L219-219)
```go
	sigHash := v.vrankPreprepareSigHash(msg.Block.NumberU64(), uint8(msg.View.Round.Uint64()), msg.Block.Hash())
```

**File:** kaiax/vrank/impl/handler.go (L230-231)
```go
	round := msg.View.Round.Uint64()
	proposer, err := v.Valset.GetProposer(blockNum, round)
```

**File:** kaiax/vrank/types.go (L50-52)
```go
func (m CPMatrix) Increment(candidate, reporter common.Address) {
	m[candidate][reporter]++
}
```

**File:** kaiax/vrank/types.go (L71-74)
```go
const (
	// MaxRound is the maximum allowed consensus round per block (range [0, MaxRound]).
	MaxRound = 10
)
```
