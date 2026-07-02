### Title
Wrong Variable in Duplicate-Beacon-Signer Error Message Exposes Staking Signer Data Instead of Beacon Signer Data - (File: module/signature/signer_indices.go)

### Summary
In `EncodeSignerToIndicesAndSigType`, the duplicate-entry check for `beaconSigners` formats its error message using `stakingSignersLookup` instead of `beaconSignersLookup`. This is a direct analog to the reported vulnerability: the wrong identifier/variable is passed to a check that is meant to operate on a different, specific entity. While the functional encoding logic itself is correct (the wrong variable only appears in the error string), the error message leaks the contents of the staking signers map when a beacon signer duplicate is detected, and conceals the actual offending beacon signer IDs. This mirrors the original report's pattern of using the wrong parameter in a critical determination.

### Finding Description

In `module/signature/signer_indices.go`, `EncodeSignerToIndicesAndSigType` builds two lookup maps and validates each for duplicates:

```go
stakingSignersLookup := stakingSigners.Lookup()
if len(stakingSignersLookup) != len(stakingSigners) {
    return nil, nil, fmt.Errorf("duplicated entries in staking signers %v", stakingSignersLookup)
}
beaconSignersLookup := beaconSigners.Lookup()
if len(beaconSignersLookup) != len(beaconSigners) {
    return nil, nil, fmt.Errorf("duplicated entries in beacon signers %v", stakingSignersLookup) // BUG: should be beaconSignersLookup
}
```

At line 85, the format argument is `stakingSignersLookup` instead of `beaconSignersLookup`. This is the exact same class of bug as the reported issue: the wrong variable (an unrelated identifier) is used in a check that is meant to operate on a specific, different entity.

The function is called from `ConsensusSigDataPacker.Pack` in `consensus/hotstuff/signature/packer.go` during QC construction, which is part of the consensus-critical path for producing Quorum Certificates. [1](#0-0) [2](#0-1) 

### Impact Explanation

The impact is **information disclosure and incorrect error attribution**:

1. **Wrong data in error**: When a caller submits a `beaconSigners` list with duplicates, the error message reports the contents of `stakingSignersLookup` (the staking signers map, which may contain sensitive node identity data) instead of `beaconSignersLookup`. This leaks staking signer node IDs in an error context where only beacon signer IDs should appear.

2. **Incorrect attribution**: The error message says "duplicated entries in beacon signers" but shows the staking signers map. This makes forensic analysis and debugging of consensus failures incorrect — operators and automated monitors cannot identify which beacon signer IDs were actually duplicated.

3. **Consensus integrity**: `EncodeSignerToIndicesAndSigType` is called during QC packing in `ConsensusSigDataPacker.Pack`. Any error here is treated as an internal exception and propagates up, potentially causing QC construction to fail with misleading diagnostic data. This can impair incident response for consensus-level issues. [3](#0-2) 

### Likelihood Explanation

The bug is triggered whenever `beaconSigners` contains duplicate node IDs. In the normal consensus path, inputs come from trusted internal components, so duplicates are not expected. However, the error path is reachable by any code that constructs `BlockSignatureData` with a duplicated `RandomBeaconSigners` list and calls `Pack`. The bug is present in production code and is not gated by any configuration flag. [4](#0-3) 

### Recommendation

On line 85 of `module/signature/signer_indices.go`, replace `stakingSignersLookup` with `beaconSignersLookup` in the format argument:

```go
// Before (incorrect):
return nil, nil, fmt.Errorf("duplicated entries in beacon signers %v", stakingSignersLookup)

// After (correct):
return nil, nil, fmt.Errorf("duplicated entries in beacon signers %v", beaconSignersLookup)
``` [1](#0-0) 

### Proof of Concept

1. Construct a `beaconSigners` list with a duplicated node ID, e.g.:
   ```go
   id := unittest.IdentifierFixture()
   beaconSigners := flow.IdentifierList{id, id}
   stakingSigners := flow.IdentifierList{unittest.IdentifierFixture()}
   committee := append(stakingSigners, id)
   _, _, err := signature.EncodeSignerToIndicesAndSigType(committee, stakingSigners, beaconSigners)
   ```
2. Observe that `err.Error()` contains `"duplicated entries in beacon signers"` but the map printed is `stakingSignersLookup` (showing the staking signer's node ID), not the beacon signer's node ID.
3. The actual offending beacon signer ID (`id`) does not appear in the error message; instead, the staking signer's ID is disclosed. [5](#0-4)

### Citations

**File:** module/signature/signer_indices.go (L79-86)
```go
	stakingSignersLookup := stakingSigners.Lookup()
	if len(stakingSignersLookup) != len(stakingSigners) {
		return nil, nil, fmt.Errorf("duplicated entries in staking signers %v", stakingSignersLookup)
	}
	beaconSignersLookup := beaconSigners.Lookup()
	if len(beaconSignersLookup) != len(beaconSigners) {
		return nil, nil, fmt.Errorf("duplicated entries in beacon signers %v", stakingSignersLookup)
	}
```

**File:** consensus/hotstuff/signature/packer.go (L33-48)
```go
func (p *ConsensusSigDataPacker) Pack(view uint64, sig *hotstuff.BlockSignatureData) ([]byte, []byte, error) {
	// retrieve all authorized consensus participants at the given block
	fullMembers, err := p.committees.IdentitiesByEpoch(view)
	if err != nil {
		return nil, nil, fmt.Errorf("could not find consensus committee for view %d: %w", view, err)
	}

	// breaking staking and random beacon signers into signerIDs and sig type for compaction
	// each signer must have its signerID and sig type stored at the same index in the two slices
	// For v2, RandomBeaconSigners is nil, as we don't track individually which nodes contributed to the random beacon
	// For v3, RandomBeaconSigners is not nil, each RandomBeaconSigner also signed staking sig, so the returned signerIDs, should
	// include both StakingSigners and RandomBeaconSigners
	signerIndices, sigType, err := signature.EncodeSignerToIndicesAndSigType(fullMembers.NodeIDs(), sig.StakingSigners, sig.RandomBeaconSigners)
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected internal error while encoding signer indices and sig types: %w", err)
	}
```
