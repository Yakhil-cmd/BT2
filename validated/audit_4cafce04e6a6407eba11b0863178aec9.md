The code is conclusive. Here is the full analysis:

---

### Title
Pre-Permissionless `verifySeals` Counts Unqualified Council Seals Toward Qualified-Set Quorum — (`blockchain/block_validator.go`)

### Summary

In `verifySeals`, the pre-permissionless branch overwrites `signerSet` with the full **council** instead of the **qualified** set, then computes the quorum threshold against `qualifiedLen`. Seals from demoted (unqualified) council members are therefore counted toward a quorum that is supposed to require 2f+1 qualified validators, violating the BFT security invariant and allowing a block to be accepted with fewer qualified-validator signatures than required.

### Finding Description

The relevant code in `blockchain/block_validator.go`:

```go
// line 294-302
signerSet := qualifiedSet.Copy()          // initially qualifiedSet …
if !rules.IsPermissionless {
    council, err := v.mValset.GetCouncil(blockNum)
    // …
    signerSet = valset.NewAddressSet(council).Copy()  // … immediately overwritten with council
}
validSeal, err := countValidCommittedSeals(committers, signerSet)  // counts council seals
``` [1](#0-0) 

Then the quorum threshold is computed against the **qualified** length, not the council length:

```go
qualifiedLen := len(qualified)
// …
if validSeal < 2*v.sealer.F(blockNum, qualifiedLen, committeeSize)+1 {
    return istanbul.ErrInvalidCommittedSeals
}
``` [2](#0-1) 

`countValidCommittedSeals` accepts any address present in `signerSet` (council) and rejects any address absent from it:

```go
func countValidCommittedSeals(committers []common.Address, signerSet *valset.AddressSet) (int, error) {
    for _, addr := range committers {
        if !signerSet.Remove(addr) {
            return 0, istanbul.ErrInvalidCommittedSeals
        }
        validSeal++
    }
``` [3](#0-2) 

Because `signerSet = council` (a superset of `qualified`), seals from council members who are **not** in the qualified set pass the per-seal check and increment `validSeal`. The quorum gate `2*F(qualifiedLen, committeeSize)+1` is then satisfied with fewer qualified-validator signatures than the BFT threshold requires.

### Impact Explanation

- **Invalid block acceptance**: A block whose committed seals include enough unqualified council members to reach the quorum threshold — even without 2f+1 qualified validators — passes `verifySeals` and is accepted as canonical.
- **Consensus divergence**: Honest nodes that enforce the correct invariant (seals must come from qualified validators) would reject the same block, causing a chain split between patched and unpatched nodes.
- **Reduced security margin**: The effective fault-tolerance threshold drops below f, because up to `|council| − |qualified|` Byzantine-or-demoted council members can substitute for qualified validators in the seal count.

This falls squarely within the allowed impact gate: *invalid block/proof acceptance* and *consensus divergence on honest nodes*.

### Likelihood Explanation

The scenario requires no key compromise. Demoted validators are still in the council list and can still run nodes, sign COMMIT messages with their own keys, and have those signatures collected into block headers by any proposer. The proposer itself only needs to be in the qualified set (the author check at line 290 uses `qualifiedSet`). Once a council member is demoted but not yet removed from the council, every block produced during that window is subject to this miscounting. [4](#0-3) 

### Recommendation

Replace the council-based `signerSet` with `qualifiedSet` for the pre-permissionless path. The initial assignment on line 294 is correct; the overwrite on lines 295–301 should be removed:

```go
// Remove the block below entirely:
if !rules.IsPermissionless {
    council, err := v.mValset.GetCouncil(blockNum)
    ...
    signerSet = valset.NewAddressSet(council).Copy()
}
```

`signerSet` should remain `qualifiedSet.Copy()` so that only qualified validators' seals count toward quorum, matching the intent of the quorum formula.

### Proof of Concept

Setup:
- `council = {A, B, C, D, E}` (5 members)
- `qualified = {A, B, C}` (3 members; D and E are demoted)
- `committeeSize = 3` (governance param)
- `F(3, 3) = ceil(3/3)−1 = 0` → quorum = `2×0+1 = 1`

Craft a header where:
- Author seal = A (qualified, passes the `qualifiedSet.Contains(author)` check)
- Committed seals = {D} (one demoted council member)

Call `verifySeals`:
1. `signerSet = council = {A,B,C,D,E}`
2. `countValidCommittedSeals([D], council)` → D is in council → `validSeal = 1`, no error
3. `1 < 2×0+1 = 1` → false → **no `ErrInvalidCommittedSeals`**

The block is accepted despite zero qualified validators providing committed seals. With larger sets (e.g., 10-member council, 7 qualified, quorum = 5), three unqualified council members plus two qualified members satisfy quorum — a block with only 2 qualified seals is accepted as having 5. [5](#0-4)

### Citations

**File:** blockchain/block_validator.go (L289-292)
```go
	qualifiedSet := valset.NewAddressSet(qualified)
	if !qualifiedSet.Contains(author) {
		return consensus.ErrUnauthorized
	}
```

**File:** blockchain/block_validator.go (L294-316)
```go
	signerSet := qualifiedSet.Copy()
	if !rules.IsPermissionless {
		council, err := v.mValset.GetCouncil(blockNum)
		if err != nil {
			return err
		}
		signerSet = valset.NewAddressSet(council).Copy()
	}
	validSeal, err := countValidCommittedSeals(committers, signerSet)
	if err != nil {
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
		return istanbul.ErrInvalidCommittedSeals
	}
```

**File:** blockchain/block_validator.go (L320-329)
```go
func countValidCommittedSeals(committers []common.Address, signerSet *valset.AddressSet) (int, error) {
	validSeal := 0
	for _, addr := range committers {
		if !signerSet.Remove(addr) {
			return 0, istanbul.ErrInvalidCommittedSeals
		}
		validSeal++
	}
	return validSeal, nil
}
```
