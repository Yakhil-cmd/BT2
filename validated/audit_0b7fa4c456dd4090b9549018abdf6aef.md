### Title
Collection Guarantee Accepted Without Cryptographic Signature Verification - (`engine/consensus/ingestion/core.go`)

### Summary

The `validateGuarantors` function in the consensus ingestion engine checks that the signer indices of a `CollectionGuarantee` decode to cluster members with sufficient stake weight, but **never verifies the cryptographic signatures** over the guarantee. The `CollectionGuarantee.Signature` field is explicitly left unverified. A single authorized collection node can therefore forge a guarantee claiming a quorum of signers without any of those signers having actually signed, causing consensus nodes to include fabricated collections in blocks and triggering execution of transactions that were never legitimately finalized by the cluster.

### Finding Description

In `engine/consensus/ingestion/core.go`, `validateGuarantors` decodes `SignerIndices` to recover the set of guarantors and checks their aggregate weight against the QC threshold: [1](#0-0) 

However, the `Signature` field of `CollectionGuarantee` — which is the BLS aggregate signature over the collection that the claimed signers produced — is **never verified**. The constructor comment in `model/flow/collectionGuarantee.go` explicitly acknowledges this: [2](#0-1) 

The `validateGuarantors` function itself carries a `TODO` comment admitting the implementation is **NOT BFT**: [3](#0-2) 

The `Signature` field is present in the struct but is never passed to any cryptographic verifier anywhere in the ingestion path: [4](#0-3) 

The protocol state's `guaranteeExtend` (called during block extension) also only calls `FindGuarantors` to decode signer indices — it does not verify the aggregate signature either: [5](#0-4) 

### Impact Explanation

A single authorized collection node can:

1. Construct a `CollectionGuarantee` with `SignerIndices` encoding a supermajority of the cluster (sufficient weight to pass the threshold check) but with a **nil or forged `Signature`**.
2. Broadcast this guarantee to consensus nodes via the `ReceiveGuarantees` channel.
3. Consensus nodes accept it into the mempool and include it in a block proposal.
4. The block is finalized and execution nodes execute the referenced collection — which may contain transactions the claimed signers never agreed to finalize.

This allows a single malicious collection node to inject arbitrary collections into the canonical chain, enabling unauthorized execution of transactions, potential fund theft (e.g. via crafted Cadence transactions), and violation of the cluster consensus guarantee that is the entire basis for collection node trust.

### Likelihood Explanation

The entry path is directly reachable: any staked collection node can send a `CollectionGuarantee` message on `channels.ReceiveGuarantees`. The network-layer `AuthorizedSenderValidator` permits collection nodes to send this message type: [6](#0-5) 

No additional privilege is required beyond being a staked collection node. The missing check is not gated by any feature flag.

### Recommendation

Implement BLS aggregate signature verification in `validateGuarantors`. The `Signature` field must be verified against the aggregate public key of the decoded guarantors (the nodes identified by `SignerIndices`) over the canonical hash of the `CollectionGuarantee`. This is the verification step the `TODO` comment defers. Until this is implemented, a single collection node can bypass the cluster consensus requirement entirely.

### Proof of Concept

1. Attacker controls one staked collection node in cluster `C`.
2. Attacker crafts:
   ```go
   guarantee := &flow.CollectionGuarantee{
       CollectionID:     <arbitrary collection hash>,
       ReferenceBlockID: <valid recent block>,
       ClusterChainID:   C.ChainID(),
       SignerIndices:    <indices encoding all cluster members>, // passes weight check
       Signature:        nil, // never verified
   }
   ```
3. Attacker's node sends this to consensus nodes on `channels.ReceiveGuarantees`.
4. `validateOrigin` passes (attacker is a valid collection node).
5. `validateGuarantors` passes: `DecodeSignerIndicesToIdentities` succeeds, total weight ≥ threshold.
6. Guarantee is added to the mempool and included in the next block proposal.
7. Execution nodes execute the collection, running attacker-chosen transactions.

The missing verification is confirmed by the explicit `TODO` at: [7](#0-6) 

and the constructor note that `Signature` is intentionally not validated: [2](#0-1)

### Citations

**File:** engine/consensus/ingestion/core.go (L149-155)
```go
//
// TODO: Eventually we should check the signatures, ensure a quorum of the
// cluster, and ensure HotStuff finalization rules. Likely a cluster-specific
// version of the follower will be a good fit for this. For now, collection
// nodes independently decide when a collection is finalized and we only check
// that the guarantors are all from the same cluster. This implementation is NOT BFT.
func (e *Core) validateGuarantors(guarantee *flow.CollectionGuarantee) error {
```

**File:** engine/consensus/ingestion/core.go (L190-195)
```go
	// determine whether signers reach minimally required stake threshold
	threshold := committees.WeightThresholdToBuildQC(clusterMembers.TotalWeight()) // compute required stake threshold
	totalStake := guarantors.TotalWeight()
	if totalStake < threshold {
		return engine.NewInvalidInputErrorf("collection guarantee qc signers have insufficient stake of %d (required=%d)", totalStake, threshold)
	}
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

**File:** model/flow/collectionGuarantee.go (L36-42)
```go
// CollectionID and ReferenceBlockID are non-zero.
// The Signature field is not validated here for the following reasons:
//
//   - Signature is currently unused and set to nil when generating a CollectionGuarantee,
//     as the consensus nodes are currently unable to easily verify it.
func NewCollectionGuarantee(untrusted UntrustedCollectionGuarantee) (*CollectionGuarantee, error) {
	if untrusted.CollectionID == ZeroID {
```

**File:** state/protocol/badger/mutator.go (L620-630)
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
	}
```

**File:** network/message/authorization.go (L479-482)
```go
	// collections, guarantees & transactions
	case *messages.CollectionGuarantee:
		return authorizationConfigs[CollectionGuarantee], nil
	case *messages.TransactionBody:
```
