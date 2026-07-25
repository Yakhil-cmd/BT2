Now I have all the information needed. Let me trace through the exact arithmetic and code paths.

### Title
Pre-permissionless `verifySeals` quorum collapses to 1 for tiny committees when governance `committeeSize` exceeds `qualifiedLen` — (`blockchain/block_validator.go`)

---

### Summary

The pre-permissionless branch of `BlockValidator.verifySeals` computes its quorum threshold as `2*sealer.F(blockNum, qualifiedLen, committeeSize)+1`. When the governance `CommitteeSize` parameter exceeds `qualifiedLen` and `qualifiedLen < 4`, `F` returns 0 and the threshold collapses to 1. The live consensus core uses `calcQuorumSize`, which has an explicit tiny-committee guard (`if size < 4 { return size }`) that returns `qualifiedLen` (e.g., 3) for the same inputs. A single malicious qualified validator can therefore craft a block carrying only their own committed seal and have it accepted by any syncing node, while the live consensus would never have committed such a block.

---

### Finding Description

**`IstanbulSealer.F`** (`consensus/istanbul/sealer.go:304-309`):

```go
func (m *IstanbulSealer) F(_ uint64, qualifiedLen, committeeSize int) int {
    if qualifiedLen > int(committeeSize) {
        return int(math.Ceil(float64(committeeSize)/3)) - 1
    }
    return int(math.Ceil(float64(qualifiedLen)/3)) - 1
}
```

With `qualifiedLen=3`, `committeeSize=10`: `3 > 10` is false, so it returns `ceil(3/3)-1 = 0`. The proof-of-concept arithmetic is exact: `2*0+1 = 1`. [1](#0-0) 

**`verifySeals` pre-permissionless branch** (`blockchain/block_validator.go:307-316`):

```go
qualifiedLen := len(qualified)
committeeSize := qualifiedLen
if !gov.DeprecatedAt(gov.IstanbulCommitteeSize, rules) {
    committeeSize = int(v.mGov.GetParamSet(blockNum).CommitteeSize)
}
if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
    return istanbul.ErrInvalidCommittedSeals
}
```

`committeeSize` is taken from the governance parameter (e.g., 10), not from the actual committee returned by `GetCommittee`. When `committeeSize > qualifiedLen`, `F` uses `qualifiedLen` in the ceiling, but the tiny-committee guard is absent. [2](#0-1) 

**`calcQuorumSize` in the live consensus core** (`consensus/istanbul/core/core.go:81-87`):

```go
func calcQuorumSize(qualifiedLen int, committeeSize uint64) int {
    size := min(qualifiedLen, int(committeeSize))
    if size < 4 {
        return size   // tiny-committee guard: everyone must sign
    }
    return int(math.Ceil(float64(2*size) / 3))
}
```

`committeeSize` here is `committeeSet.Len()` — the actual committee returned by `GetCommittee`, which equals `qualifiedLen` when `qualifiedLen <= governance committeeSize`. So `calcQuorumSize(3, 3) = 3`. [3](#0-2) 

The live consensus also uses the actual committee size, not the governance parameter: [4](#0-3) 

**`IstanbulSealer.Quorum`** itself has the tiny-committee guard (`if n < 4 { return n }`), but `verifySeals` bypasses `Quorum` entirely in the pre-permissionless branch and calls `F` directly, losing that guard. [5](#0-4) 

The condition `committeeSize > qualifiedLen` is reachable without any special privilege: the default governance `CommitteeSize` is 21 (`DefaultValue: uint64(21)`). If a network loses validators through demotion until `qualifiedLen` drops below 4 while the governance parameter stays at 21, the condition is satisfied automatically. [6](#0-5) 

---

### Impact Explanation

A syncing node importing a block via P2P/downloader calls `validateHeader` → `verifySeals`. With `qualifiedLen=3` and governance `committeeSize=10`, the check passes with `validSeal=1`. The live consensus would never commit such a block (it requires 3 seals). The result is **invalid block acceptance** and **consensus divergence**: syncing nodes accept a block that honest live-consensus nodes would reject, splitting the canonical chain.

---

### Likelihood Explanation

The condition requires: (a) pre-permissionless era, (b) `qualifiedLen < 4`, (c) governance `CommitteeSize > qualifiedLen`. Condition (c) is the default state for any network that started with the default `CommitteeSize=21` and later lost validators. The attacker must be a single qualified validator — not majority collusion. They craft a block with only their own committed seal and serve it to syncing peers via P2P.

---

### Recommendation

Replace the raw `2*F+1` formula in the pre-permissionless branch with a call that respects the tiny-committee guard. The simplest fix is to use `sealer.Quorum(blockNum, qualifiedLen, committeeSize)` directly (which already has `if n < 4 { return n }`), or inline the same guard:

```go
effectiveSize := min(qualifiedLen, committeeSize)
var threshold int
if effectiveSize < 4 {
    threshold = effectiveSize
} else {
    threshold = 2*v.sealer.F(blockNum, qualifiedLen, committeeSize) + 1
}
if validSeal < threshold {
    return istanbul.ErrInvalidCommittedSeals
}
```

---

### Proof of Concept

```
qualifiedLen  = 3
committeeSize = 10   // governance parameter, default=21, unchanged after validator loss

F(3, 10):
  3 > 10? No
  → ceil(3/3) - 1 = 1 - 1 = 0

verifySeals threshold = 2*0+1 = 1

calcQuorumSize(3, 3):   // live consensus uses actual committee size = 3
  size = min(3,3) = 3
  3 < 4 → return 3

Live consensus requires 3 seals; block validator accepts 1.

Attack:
1. Malicious qualified validator proposes block B at height H.
2. Attaches only their own committed seal (1 seal, cryptographically valid).
3. Serves block B directly to syncing peers via P2P.
4. Syncing node calls verifySeals: validSeal=1 >= threshold=1 → accepted.
5. Syncing node builds canonical chain on top of B; honest live-consensus
   nodes never committed B (required 3 seals) → consensus divergence.
```

### Citations

**File:** consensus/istanbul/sealer.go (L304-309)
```go
func (m *IstanbulSealer) F(_ uint64, qualifiedLen, committeeSize int) int {
	if qualifiedLen > int(committeeSize) {
		return int(math.Ceil(float64(committeeSize)/3)) - 1
	}
	return int(math.Ceil(float64(qualifiedLen)/3)) - 1
}
```

**File:** consensus/istanbul/sealer.go (L315-321)
```go
func (m *IstanbulSealer) Quorum(_ uint64, qualifiedlen, committeeSize int) int {
	n := min(qualifiedlen, committeeSize)
	if n < 4 {
		return n
	}
	return int(math.Ceil(float64(2*n) / 3))
}
```

**File:** blockchain/block_validator.go (L307-316)
```go
	qualifiedLen := len(qualified)
	committeeSize := qualifiedLen
	if !gov.DeprecatedAt(gov.IstanbulCommitteeSize, rules) {
		committeeSize = int(v.mGov.GetParamSet(blockNum).CommitteeSize)
	}
	// Pre-permissionless uses the legacy 2f+1 quorum. sealer.Quorum now returns
	// ceil(2N/3), so compute 2f+1 explicitly to preserve historical header validity.
	if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
		return istanbul.ErrInvalidCommittedSeals
	}
```

**File:** consensus/istanbul/core/core.go (L68-73)
```go
	committeeSet = valset.NewAddressSet(committeeAddrs)
	committeeSize = uint64(committeeSet.Len())

	qLen := qualified.Len()
	requiredMsgCnt = calcQuorumSize(qLen, committeeSize)
	fNum = calcFaultTolerance(qLen, committeeSize)
```

**File:** consensus/istanbul/core/core.go (L81-87)
```go
func calcQuorumSize(qualifiedLen int, committeeSize uint64) int {
	size := min(qualifiedLen, int(committeeSize))
	if size < 4 {
		return size
	}
	return int(math.Ceil(float64(2*size) / 3))
}
```

**File:** kaiax/gov/param.go (L265-281)
```go
	IstanbulCommitteeSize: {
		Canonicalizer: uint64Canonicalizer,
		FormatChecker: func(cv any) bool {
			v, ok := cv.(uint64)
			if !ok {
				return false
			}
			return v > 0
		},
		ChainConfigValue: func(c *params.ChainConfig) (any, error) {
			if c.Istanbul == nil {
				return nil, errors.New("istanbul is not set")
			}
			return c.Istanbul.SubGroupSize, nil
		},
		DefaultValue: uint64(21),
	},
```
