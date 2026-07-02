### Title
Unenforced Collection Guarantee Signature Requirement — (`model/flow/collectionGuarantee.go`, `engine/consensus/ingestion/core.go`, `module/finalizer/collection/finalizer.go`)

### Summary

The `CollectionGuarantee.Signature` field exists to cryptographically attest that a quorum of collection cluster members signed off on a collection. However, this signature is **never verified** anywhere in the consensus ingestion or block extension pipeline. The field is explicitly set to `nil` when guarantees are produced, and the constructor explicitly documents that it is "currently unused." This is a direct analog to the Neptune Mutual unenforced staking requirement: a security requirement (cryptographic proof of cluster quorum) is structurally present but never enforced, allowing any authorized collection node to forge a guarantee claiming any set of signers without producing a valid aggregate BLS signature.

### Finding Description

`CollectionGuarantee` carries a `Signature crypto.Signature` field intended to hold an aggregated BLS signature from the cluster members listed in `SignerIndices`.

**Root cause 1 — Signature is set to `nil` at production time:**

In `module/finalizer/collection/finalizer.go` line 187, when a finalized cluster block is converted into a `CollectionGuarantee` to be pushed to consensus nodes, the `Signature` field is explicitly set to `nil`:

```go
guarantee, err := flow.NewCollectionGuarantee(flow.UntrustedCollectionGuarantee{
    ...
    Signature: nil, // TODO: to remove because it's not easily verifiable by consensus nodes
})
```

**Root cause 2 — Signature is never verified at ingestion:**

In `engine/consensus/ingestion/core.go`, `validateGuarantors()` (lines 155–198) checks only that:
- The `ClusterChainID` maps to a known cluster
- The `SignerIndices` decode to valid cluster member identities
- The decoded guarantors' total weight meets the QC threshold

It **never verifies** `guarantee.Signature` against the decoded guarantors' public keys. The TODO comment at line 150–154 explicitly acknowledges this:

> "TODO: Eventually we should check the signatures, ensure a quorum of the cluster, and ensure HotStuff finalization rules. For now, collection nodes independently decide when a collection is finalized and we only check that the guarantors are all from the same cluster. This implementation is NOT BFT."

**Root cause 3 — Signature is not validated in the constructor:**

`NewCollectionGuarantee` in `model/flow/collectionGuarantee.go` (lines 37–40) explicitly documents:

> "Signature is currently unused and set to nil when generating a CollectionGuarantee, as the consensus nodes are currently unable to easily verify it."

**Root cause 4 — Block extension also skips signature verification:**

`guaranteeExtend()` in `state/protocol/badger/mutator.go` (lines 556–633) calls `protocol.FindGuarantors()` which only decodes signer indices — it never verifies the aggregate BLS signature over the collection hash.

### Impact Explanation

An authorized (staked) collection node can craft a `CollectionGuarantee` with:
- A valid `CollectionID` (any collection hash)
- A valid `ReferenceBlockID`
- A valid `ClusterChainID`
- `SignerIndices` encoding a supermajority of cluster members (meeting the weight threshold)
- `Signature = nil` or any arbitrary bytes

This guarantee will pass all validation in `validateGuarantors()` and `guaranteeExtend()` and be accepted into the consensus mempool and included in finalized blocks. The result is that **a single malicious collection node can cause arbitrary collections to be finalized and executed without a genuine quorum of cluster members having agreed**, bypassing the cluster consensus requirement entirely. Execution nodes will then fetch and execute the collection, treating it as legitimately guaranteed.

### Likelihood Explanation

The attack requires a single staked collection node (any cluster member). The entry path is the standard p2p gossip channel used to submit `CollectionGuarantee` messages to consensus nodes. No special privileges beyond being a staked collection node are needed. The `validateOrigin()` check only confirms the sender is an authorized collection node — it does not require the sender to be one of the listed guarantors. The attack is straightforward to execute by any collection node operator.

### Recommendation

1. Implement BLS aggregate signature verification in `validateGuarantors()` using the decoded guarantors' `StakingPubKey` values and the collection hash as the signed message.
2. Remove the `Signature: nil` assignment in `module/finalizer/collection/finalizer.go` and produce a real aggregate BLS signature from the cluster's HotStuff QC over the collection block.
3. Add signature validation to `NewCollectionGuarantee` once verification is implemented.
4. Add signature verification to `guaranteeExtend()` in `state/protocol/badger/mutator.go`.

### Proof of Concept

A staked collection node sends the following `CollectionGuarantee` over the p2p network to consensus nodes:

```go
// Attacker constructs a guarantee claiming all cluster members signed
allMemberIndices, _ := signature.EncodeSignersToIndices(clusterMemberIDs, clusterMemberIDs)

forgedGuarantee, _ := flow.NewCollectionGuarantee(flow.UntrustedCollectionGuarantee{
    CollectionID:     targetCollectionID,   // any collection hash
    ReferenceBlockID: recentBlockID,
    ClusterChainID:   clusterChainID,
    SignerIndices:    allMemberIndices,      // claims full quorum
    Signature:        nil,                  // no real signature needed
})
// Submit via p2p to consensus node's ingestion engine
```

`Core.OnGuarantee()` calls `validateOrigin()` (passes — sender is a valid collection node), `validateExpiry()` (passes — reference block is recent), and `validateGuarantors()`:

- `DecodeSignerIndicesToIdentities` succeeds — indices are valid
- `guarantors.TotalWeight() >= threshold` — full cluster weight claimed, passes
- **No BLS signature check is performed**

The guarantee is added to the mempool and included in the next block proposal. `guaranteeExtend()` in `state/protocol/badger/mutator.go` calls `FindGuarantors()` which again only decodes indices without verifying the signature. The block is accepted and the forged collection is finalized. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** model/flow/collectionGuarantee.go (L37-40)
```go
// The Signature field is not validated here for the following reasons:
//
//   - Signature is currently unused and set to nil when generating a CollectionGuarantee,
//     as the consensus nodes are currently unable to easily verify it.
```

**File:** module/finalizer/collection/finalizer.go (L180-188)
```go
			// TODO add real signatures here (https://github.com/onflow/flow-go-internal/issues/4569)
			// TODO: after adding real signature here add check for signature in NewCollectionGuarantee
			guarantee, err := flow.NewCollectionGuarantee(flow.UntrustedCollectionGuarantee{
				CollectionID:     payload.Collection.ID(),
				ReferenceBlockID: payload.ReferenceBlockID,
				ClusterChainID:   header.ChainID,
				SignerIndices:    step.ParentVoterIndices,
				Signature:        nil, // TODO: to remove because it's not easily verifiable by consensus nodes
			})
```

**File:** engine/consensus/ingestion/core.go (L150-197)
```go
// TODO: Eventually we should check the signatures, ensure a quorum of the
// cluster, and ensure HotStuff finalization rules. Likely a cluster-specific
// version of the follower will be a good fit for this. For now, collection
// nodes independently decide when a collection is finalized and we only check
// that the guarantors are all from the same cluster. This implementation is NOT BFT.
func (e *Core) validateGuarantors(guarantee *flow.CollectionGuarantee) error {
	// get the clusters to assign the guarantee and check if the guarantor is part of it
	snapshot := e.state.AtBlockID(guarantee.ReferenceBlockID)
	epoch, err := snapshot.Epochs().Current()
	if err != nil {
		return fmt.Errorf("could not get current epoch: %w", err)
	}
	cluster, err := epoch.ClusterByChainID(guarantee.ClusterChainID)
	// reference block not found
	if errors.Is(err, state.ErrUnknownSnapshotReference) {
		return engine.NewUnverifiableInputError(
			"could not get clusters with chainID %v for unknown reference block (id=%x): %w", guarantee.ClusterChainID, guarantee.ReferenceBlockID, err)
	}
	// cluster not found by the chain ID
	if errors.Is(err, protocol.ErrClusterNotFound) {
		return engine.NewInvalidInputErrorf("cluster not found by chain ID %v: %w", guarantee.ClusterChainID, err)
	}
	if err != nil {
		return fmt.Errorf("internal error retrieving collector clusters for guarantee (ReferenceBlockID: %v, ClusterChainID: %v): %w",
			guarantee.ReferenceBlockID, guarantee.ClusterChainID, err)
	}

	// ensure the guarantors are from the same cluster
	clusterMembers := cluster.Members().ToSkeleton()

	// find guarantors by signer indices
	guarantors, err := signature.DecodeSignerIndicesToIdentities(clusterMembers, guarantee.SignerIndices)
	if err != nil {
		if signature.IsInvalidSignerIndicesError(err) {
			return engine.NewInvalidInputErrorf("could not decode guarantor indices: %w", err)
		}
		// unexpected error
		return fmt.Errorf("unexpected internal error decoding signer indices: %w", err)
	}

	// determine whether signers reach minimally required stake threshold
	threshold := committees.WeightThresholdToBuildQC(clusterMembers.TotalWeight()) // compute required stake threshold
	totalStake := guarantors.TotalWeight()
	if totalStake < threshold {
		return engine.NewInvalidInputErrorf("collection guarantee qc signers have insufficient stake of %d (required=%d)", totalStake, threshold)
	}

	return nil
```

**File:** state/protocol/badger/mutator.go (L619-629)
```go

		// check the guarantors are correct
		_, err = protocol.FindGuarantors(m, guarantee)
		if err != nil {
			if signature.IsInvalidSignerIndicesError(err) ||
				errors.Is(err, protocol.ErrNextEpochNotCommitted) ||
				errors.Is(err, protocol.ErrClusterNotFound) {
				return state.NewInvalidExtensionErrorf("guarantee %v contains invalid guarantors: %w", guarantee.ID(), err)
			}
			return fmt.Errorf("could not find guarantor for guarantee %v: %w", guarantee.ID(), err)
		}
```

**File:** state/protocol/util.go (L96-115)
```go
func FindGuarantors(state State, guarantee *flow.CollectionGuarantee) ([]flow.Identifier, error) {
	snapshot := state.AtBlockID(guarantee.ReferenceBlockID)
	epoch, err := snapshot.Epochs().Current()
	if err != nil {
		return nil, fmt.Errorf("could not get current epoch: %w", err)
	}
	cluster, err := epoch.ClusterByChainID(guarantee.ClusterChainID)

	if err != nil {
		return nil, fmt.Errorf(
			"fail to retrieve collector clusters for guarantee (ReferenceBlockID: %v, ClusterChainID: %v): %w",
			guarantee.ReferenceBlockID, guarantee.ClusterChainID, err)
	}

	guarantorIDs, err := signature.DecodeSignerIndicesToIdentifiers(cluster.Members().NodeIDs(), guarantee.SignerIndices)
	if err != nil {
		return nil, fmt.Errorf("could not decode signer indices for guarantee %v: %w", guarantee.ID(), err)
	}

	return guarantorIDs, nil
```
