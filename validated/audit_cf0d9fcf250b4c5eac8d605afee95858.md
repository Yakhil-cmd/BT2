### Title
Unverified `CollectionGuarantee.Signature` Allows a Malicious Collection Node to Forge Signer Quorum — (`engine/consensus/ingestion/core.go`)

### Summary

The consensus ingestion engine accepts `CollectionGuarantee` messages from collection nodes and validates that the claimed signers have sufficient stake weight, but **never verifies the cryptographic signature** attached to the guarantee. A single malicious collection node can forge the `SignerIndices` field to claim a supermajority of its cluster signed a collection, bypassing the BFT quorum requirement entirely.

### Finding Description

`validateGuarantors` in `engine/consensus/ingestion/core.go` performs two checks on an incoming `CollectionGuarantee`:

1. Decodes `SignerIndices` to a list of cluster member identities.
2. Checks that the total weight of those claimed signers meets the `WeightThresholdToBuildQC` threshold. [1](#0-0) 

It does **not** verify `guarantee.Signature` against the claimed signers. The `CollectionGuarantee` struct carries a `Signature` field: [2](#0-1) 

but the constructor explicitly documents that this field is never validated: [3](#0-2) 

The collection finalizer confirms this by setting `Signature: nil` when constructing guarantees: [4](#0-3) 

The ingestion engine's own comment acknowledges the gap: [5](#0-4) 

This is the direct analog to the Ethereum bridge's `ecrecover` return-value omission: in both cases, a claimed set of signers is accepted as meeting the threshold without any cryptographic proof that those signers actually signed the payload.

### Impact Explanation

A single malicious collection node can:

1. Construct a `CollectionGuarantee` for any collection (including one it alone finalized, or one containing adversarially ordered transactions).
2. Set `SignerIndices` to encode a supermajority of the cluster (e.g., all members), satisfying the weight threshold check.
3. Leave `Signature` as `nil` or any arbitrary bytes.
4. Submit this to a consensus node via `channels.PushGuarantees`.

`validateOrigin` passes because the sender is an authorized collection node. `validateGuarantors` passes because the weight of the *claimed* signers meets the threshold. The guarantee is added to the mempool and included in a block proposal, bypassing the cluster's HotStuff BFT finalization requirement entirely. [6](#0-5) 

### Likelihood Explanation

Any staked collection node that turns malicious (or is operated by an adversary from the start) can immediately exploit this. No key compromise, quorum collusion, or social engineering is required — the attacker only needs to be a single authorized collection node. The `validateOrigin` check is the only gate, and it is satisfied by the attacker's own node identity. [7](#0-6) 

### Recommendation

**Short term:** In `validateGuarantors`, verify `guarantee.Signature` against the decoded guarantor public keys before accepting the guarantee. Reject any guarantee whose signature is nil or fails cryptographic verification.

**Long term:** Complete the tracked TODO to implement proper BFT verification of collection guarantees, including HotStuff finalization rules for the cluster chain, as noted in the existing comments. [5](#0-4) 

### Proof of Concept

```
1. Attacker operates a staked collection node in cluster C.
2. Attacker constructs:
     guarantee := &flow.CollectionGuarantee{
         CollectionID:     <arbitrary collection ID>,
         ReferenceBlockID: <valid recent block>,
         ClusterChainID:   <cluster C chain ID>,
         SignerIndices:    <encoded indices of ALL cluster C members>,
         Signature:        nil,   // never checked
     }
3. Attacker sends guarantee to a consensus node on channels.PushGuarantees.
4. validateOrigin: passes (attacker is an authorized collection node).
5. validateGuarantors:
     - DecodeSignerIndicesToIdentities returns all cluster members.
     - TotalWeight() >= WeightThresholdToBuildQC → passes.
     - guarantee.Signature is never read.
6. Guarantee is added to the mempool and included in the next block proposal,
   with no actual quorum of cluster C having signed it.
``` [8](#0-7) [9](#0-8)

### Citations

**File:** engine/consensus/ingestion/core.go (L61-109)
```go
func (e *Core) OnGuarantee(originID flow.Identifier, guarantee *flow.CollectionGuarantee) error {

	span, _ := e.tracer.StartCollectionSpan(context.Background(), guarantee.CollectionID, trace.CONIngOnCollectionGuarantee)
	span.SetAttributes(
		attribute.String("originID", originID.String()),
	)
	defer span.End()

	log := e.log.With().
		Hex("origin_id", originID[:]).
		Hex("collection_id", guarantee.CollectionID[:]).
		Hex("signers", guarantee.SignerIndices).
		Logger()
	log.Info().Msg("collection guarantee received")

	guaranteeID := guarantee.ID()

	// skip collection guarantees that are already in our memory pool
	exists := e.pool.Has(guaranteeID)
	if exists {
		log.Debug().Msg("skipping known collection guarantee")
		return nil
	}

	// check collection guarantee's validity
	err := e.validateOrigin(originID, guarantee) // retrieve and validate the sender of the collection guarantee
	if err != nil {
		return fmt.Errorf("origin validation error: %w", err)
	}
	err = e.validateExpiry(guarantee) // ensure that collection has not expired
	if err != nil {
		return fmt.Errorf("expiry validation error: %w", err)
	}
	err = e.validateGuarantors(guarantee) // ensure the guarantors are allowed to produce this collection
	if err != nil {
		return fmt.Errorf("guarantor validation error: %w", err)
	}

	// at this point, we can add the guarantee to the memory pool
	added := e.pool.Add(guaranteeID, guarantee)
	if !added {
		log.Debug().Msg("discarding guarantee already in pool")
		return nil
	}
	log.Info().Msg("collection guarantee added to pool")

	e.mempool.MempoolEntries(metrics.ResourceGuarantee, e.pool.Size())
	return nil
}
```

**File:** engine/consensus/ingestion/core.go (L150-154)
```go
// TODO: Eventually we should check the signatures, ensure a quorum of the
// cluster, and ensure HotStuff finalization rules. Likely a cluster-specific
// version of the follower will be a good fit for this. For now, collection
// nodes independently decide when a collection is finalized and we only check
// that the guarantors are all from the same cluster. This implementation is NOT BFT.
```

**File:** engine/consensus/ingestion/core.go (L177-198)
```go
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
}
```

**File:** engine/consensus/ingestion/core.go (L213-226)
```go
func (e *Core) validateOrigin(originID flow.Identifier, guarantee *flow.CollectionGuarantee) error {
	refState := e.state.AtBlockID(guarantee.ReferenceBlockID)
	valid, err := protocol.IsNodeAuthorizedWithRoleAt(refState, originID, flow.RoleCollection)
	if err != nil {
		// collection with an unknown reference block is unverifiable
		if errors.Is(err, state.ErrUnknownSnapshotReference) {
			return engine.NewUnverifiableInputError("could not get origin (id=%x) for unknown reference block (id=%x): %w", originID, guarantee.ReferenceBlockID, err)
		}
		return fmt.Errorf("unexpected error checking collection origin %x at reference block %x: %w", originID, guarantee.ReferenceBlockID, err)
	}
	if !valid {
		return engine.NewInvalidInputErrorf("invalid collection origin (id=%x)", originID)
	}
	return nil
```

**File:** model/flow/collectionGuarantee.go (L13-19)
```go
type CollectionGuarantee struct {
	CollectionID     Identifier       // ID of the collection being guaranteed
	ReferenceBlockID Identifier       // defines expiry of the collection
	ClusterChainID   ChainID          // the chainID of the cluster in order to determine which cluster this guarantee belongs to
	SignerIndices    []byte           // encoded indices of the signers
	Signature        crypto.Signature // guarantor signatures
}
```

**File:** model/flow/collectionGuarantee.go (L37-64)
```go
// The Signature field is not validated here for the following reasons:
//
//   - Signature is currently unused and set to nil when generating a CollectionGuarantee,
//     as the consensus nodes are currently unable to easily verify it.
func NewCollectionGuarantee(untrusted UntrustedCollectionGuarantee) (*CollectionGuarantee, error) {
	if untrusted.CollectionID == ZeroID {
		return nil, fmt.Errorf("CollectionID must not be empty")
	}

	if untrusted.ReferenceBlockID == ZeroID {
		return nil, fmt.Errorf("ReferenceBlockID must not be empty")
	}

	if len(untrusted.SignerIndices) == 0 {
		return nil, fmt.Errorf("SignerIndices must not be empty")
	}

	if len(untrusted.ClusterChainID) == 0 {
		return nil, fmt.Errorf("ClusterChainID must not be empty")
	}

	return &CollectionGuarantee{
		CollectionID:     untrusted.CollectionID,
		ReferenceBlockID: untrusted.ReferenceBlockID,
		ClusterChainID:   untrusted.ClusterChainID,
		SignerIndices:    untrusted.SignerIndices,
		Signature:        untrusted.Signature,
	}, nil
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
