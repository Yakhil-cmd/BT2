Let me look at the `Quorum` function usage and the `F` function more carefully, plus check how `GetQualifiedValidators` and `GetCouncil` interact.

Now I have all the code I need. Let me trace the exact math and call path.

**`F` function** (`consensus/istanbul/sealer.go:304-309`):
```
F(_, 3, 3): qualifiedLen(3) > committeeSize(3) → false
→ return ceil(3/3) - 1 = 1 - 1 = 0
```

**Pre-permissionless quorum check** (`blockchain/block_validator.go:314`):
```
validSeal < 2*F(blockNum,3,3)+1
= validSeal < 2*0+1
= validSeal < 1
→ passes with validSeal=1 (a single committed seal)
```

**Live consensus quorum** (`consensus/istanbul/core/core.go:81-87`):
```
calcQuorumSize(3, 3): size=3, size<4 → return 3
```

**Post-permissionless `Quorum`** (`consensus/istanbul/sealer.go:315-321`):
```
Quorum(_, 3, 3): n=3, n<4 → return 3
```

The discrepancy is real and confirmed: the live consensus core and the post-permissionless validator both require **3** seals for N=3, but the pre-permissionless `verifySeals` path requires only **1**.

---

### Title
Pre-permissionless `verifySeals` accepts blocks with a single committed seal when `qualifiedLen ≤ 3`, violating BFT quorum — (`blockchain/block_validator.go`)

### Summary

`IstanbulSealer.F` returns `0` for any `qualifiedLen ∈ {1,2,3}`, making the pre-permissionless quorum check `2*F+1 = 1`. A single malicious validator can craft and broadcast a block carrying only their own committed seal; every importing node's `verifySeals` accepts it, while the live consensus core and the post-permissionless path both correctly require `N` seals (all validators) for `N < 4`.

### Finding Description

`IstanbulSealer.F` computes:

```go
// consensus/istanbul/sealer.go:304-309
func (m *IstanbulSealer) F(_ uint64, qualifiedLen, committeeSize int) int {
    if qualifiedLen > int(committeeSize) {
        return int(math.Ceil(float64(committeeSize)/3)) - 1
    }
    return int(math.Ceil(float64(qualifiedLen)/3)) - 1
}
```

For `qualifiedLen=3, committeeSize=3`: `ceil(3/3)-1 = 0`.

The pre-permissionless branch of `verifySeals` uses this directly:

```go
// blockchain/block_validator.go:314
if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
```

`2*0+1 = 1`, so any block with at least one valid committed seal from a council member passes.

The live consensus core uses `calcQuorumSize`:

```go
// consensus/istanbul/core/core.go:81-87
func calcQuorumSize(qualifiedLen int, committeeSize uint64) int {
    size := min(qualifiedLen, int(committeeSize))
    if size < 4 {
        return size   // returns 3 for N=3
    }
    ...
}
```

And the post-permissionless `verifySeals` uses `sealer.Quorum`:

```go
// consensus/istanbul/sealer.go:315-321
func (m *IstanbulSealer) Quorum(_ uint64, qualifiedlen, committeeSize int) int {
    n := min(qualifiedlen, committeeSize)
    if n < 4 {
        return n   // returns 3 for N=3
    }
    ...
}
```

Both correctly return `3` for `N=3`. Only the pre-permissionless path is broken.

The same undercount applies to `N=1` (`ceil(1/3)-1=0`) and `N=2` (`ceil(2/3)-1=0`), making the effective quorum `1` for all small committees.

### Impact Explanation

A single malicious validator in a pre-permissionless network with `qualifiedLen ≤ 3` can:

1. Craft a block at any height where they are the proposer (author seal valid, passes `qualifiedSet.Contains(author)` check).
2. Embed only their own committed seal in `IstanbulExtra.CommittedSeal`.
3. Broadcast the block via P2P.
4. Every peer that imports the block via sync calls `verifySeals`, which computes `validSeal=1 >= 1` and accepts it.

This constitutes **invalid block acceptance** and **consensus divergence**: honest nodes that participated in live consensus (requiring 3 seals) hold a different canonical block than syncing nodes that received the crafted single-seal block first. BFT safety is broken — two conflicting blocks at the same height can both pass header validation on different nodes.

### Likelihood Explanation

- Requires a pre-permissionless network (historical or not-yet-upgraded chain).
- Requires `qualifiedLen ≤ 3` — small testnets, service chains, or early-stage networks are common in this range.
- Requires a single malicious validator (not majority collusion). The attacker only needs their own key, which they legitimately hold.
- The attack is delivered through the standard P2P block-propagation path, requiring no special access beyond being a council member.

### Recommendation

Replace the `2*F+1` expression in the pre-permissionless branch with the same small-N guard used by `calcQuorumSize` and `Quorum`:

```go
// blockchain/block_validator.go
n := min(qualifiedLen, committeeSize)
var required int
if n < 4 {
    required = n
} else {
    required = 2*v.sealer.F(blockNum, qualifiedLen, committeeSize) + 1
}
if validSeal < required {
    return istanbul.ErrInvalidCommittedSeals
}
```

Alternatively, expose a dedicated `LegacyQuorum` method on `IstanbulSealer` that applies the same `n<4 → n` guard, keeping the formula consistent across all three call sites.

### Proof of Concept

Property test asserting `2*F(n,n)+1 >= calcQuorumSize(n,n)` for all `n ∈ [1..10]`:

| n | F(n,n) | 2F+1 | calcQuorumSize(n,n) | Pass? |
|---|--------|------|----------------------|-------|
| 1 | 0      | 1    | 1                    | ✓     |
| 2 | 0      | 1    | 2                    | **✗** |
| 3 | 0      | 1    | 3                    | **✗** |
| 4 | 1      | 3    | 3                    | ✓     |
| 5 | 1      | 3    | 4                    | **✗** |
| 6 | 1      | 3    | 4                    | **✗** |
| 7 | 2      | 5    | 5                    | ✓     |
| 8 | 2      | 5    | 6                    | **✗** |
| 9 | 2      | 5    | 6                    | **✗** |
|10 | 3      | 7    | 7                    | ✓     |

The invariant `2*F(n,n)+1 >= calcQuorumSize(n,n)` fails for `n ∈ {2,3,5,6,8,9}`. For `n=3` specifically, `verifySeals` requires 1 seal while the live consensus requires 3.

**Concrete call path:** [1](#0-0) 

`verifySeals` (pre-permissionless branch): [2](#0-1) 

`IstanbulSealer.F` returning 0 for qualifiedLen=3: [3](#0-2) 

Live consensus quorum (correctly returns 3 for N=3): [4](#0-3) 

Post-permissionless `Quorum` (correctly returns 3 for N=3): [5](#0-4)

### Citations

**File:** blockchain/block_validator.go (L304-314)
```go
		return err
	}

	qualifiedLen := len(qualified)
	committeeSize := qualifiedLen
	if !gov.DeprecatedAt(gov.IstanbulCommitteeSize, rules) {
		committeeSize = int(v.mGov.GetParamSet(blockNum).CommitteeSize)
	}
	// Pre-permissionless uses the legacy 2f+1 quorum. sealer.Quorum now returns
	// ceil(2N/3), so compute 2f+1 explicitly to preserve historical header validity.
	if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
```

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
