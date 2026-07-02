### Title
Ejected Collection Node Bypasses Vote/Timeout Validation via Stale Historical Membership Check - (File: `consensus/hotstuff/committees/cluster_committee.go`)

### Summary

`Cluster.IdentityByEpoch` in the cluster committee implementation checks only whether a node was ever listed in the initial cluster membership at epoch setup time, without verifying whether the node is currently active (i.e., not ejected mid-epoch). This is the direct analog of the Solidity `subDir[author][ref] != 0` pattern: a historical existence check instead of a current-validity check. An ejected collection node can pass this check and have its votes and timeouts accepted by the HotStuff validator, undermining the ejection mechanism for cluster consensus.

### Finding Description

`Cluster.IdentityByEpoch` is defined as:

```go
func (c *Cluster) IdentityByEpoch(view uint64, participantID flow.Identifier) (*flow.IdentitySkeleton, error) {
    identity, ok := c.clusterMembers.ByNodeID(participantID)
    if !ok {
        return nil, model.NewInvalidSignerErrorf("node %v is not an authorized hotstuff participant", participantID)
    }
    return identity, nil
}
```

`c.clusterMembers` is a `flow.IdentitySkeletonList` populated once at cluster initialization from the EpochSetup event. It contains only static identity data (no `EpochParticipationStatus`). The check `c.clusterMembers.ByNodeID(participantID)` succeeds for any node that was ever listed in the EpochSetup event, regardless of whether that node has since been ejected mid-epoch.

By contrast, `IdentityByBlock` correctly applies `c.clusterMemberFilter`, which includes `filter.IsValidCurrentEpochParticipant` (requiring `EpochParticipationStatusActive`), and queries the live protocol state snapshot:

```go
if !c.clusterMemberFilter(identity) {
    return nil, model.NewInvalidSignerErrorf("node %v is not an authorized hotstuff cluster member", nodeID)
}
```

The existing test suite in `cluster_committee_test.go` explicitly documents and confirms this asymmetry:

- `IdentityByBlock` returns `InvalidSignerError` for both ejected and leaving cluster members.
- `IdentityByEpoch` returns **no error** and returns the identity for both ejected and leaving cluster members.

The `votingClusterParticipants` helper comment acknowledges that ejections occurring *before* EpochSetup are reflected in the setup event, but makes no claim about mid-epoch ejections. Mid-epoch ejections are a supported protocol operation (nodes can be ejected for misbehavior at any time), and `IdentityByBlock` exists precisely to handle them.

`IdentityByEpoch` is called from the HotStuff validator (`consensus/hotstuff/validator/validator.go`) and safety rules (`consensus/hotstuff/safetyrules/safety_rules.go`) for vote and timeout validation. Because `IdentityByEpoch` does not reject ejected nodes, an ejected collection node's votes and timeouts pass identity validation and are counted toward QC and TC formation.

### Impact Explanation

An ejected collection node — one removed from the network for misbehavior — can continue to submit votes and timeout objects to its cluster. Because `IdentityByEpoch` accepts any node that was ever listed in the EpochSetup event, the ejected node's contributions pass the identity check and are counted with their original `InitialWeight` toward quorum thresholds. The quorum threshold (`weightThresholdForQC`) is also static and does not decrease when a node is ejected, so the ejected node's weight still counts toward the same threshold. This allows an ejected node to influence or assist in forming QCs and TCs in cluster consensus, directly undermining the protocol's ejection enforcement for collection clusters.

### Likelihood Explanation

Mid-epoch ejection of collection nodes is a supported and expected protocol operation. A node ejected for misbehavior has a clear incentive to continue participating (e.g., to collude with other nodes to form a malicious QC). The ejected node retains its network keys and cluster membership credentials from the EpochSetup event, so it can continue sending valid-looking votes. No privileged access or key compromise is required beyond the ejected node's own existing credentials.

### Recommendation

`IdentityByEpoch` must check the current dynamic participation status of the node, not just its historical presence in `c.clusterMembers`. Since `c.clusterMembers` is a `IdentitySkeletonList` (no dynamic state), the fix requires either:

1. Storing `initialClusterIdentities` (the full `IdentityList` with `EpochParticipationStatus`) and checking `IsValidCurrentEpochParticipant` at call time, or
2. Querying the live protocol state (as `IdentityByBlock` does) to obtain the current dynamic identity.

The simplest fix consistent with the existing design is to use `c.initialClusterIdentities` (which already stores full identities) and apply the same `c.clusterMemberFilter` used by `IdentityByBlock`:

```go
func (c *Cluster) IdentityByEpoch(view uint64, participantID flow.Identifier) (*flow.IdentitySkeleton, error) {
    identity, ok := c.initialClusterIdentities.ByNodeID(participantID)
    if !ok || !c.clusterMemberFilter(identity) {
        return nil, model.NewInvalidSignerErrorf("node %v is not an authorized hotstuff participant", participantID)
    }
    return &identity.IdentitySkeleton, nil
}
```

### Proof of Concept

The existing test in `consensus/hotstuff/committees/cluster_committee_test.go` already demonstrates the issue:

```go
// realEjectedClusterMember has EpochParticipationStatus = EpochParticipationStatusEjected
suite.Run("should return ErrInvalidSigner for existent but ejected cluster member", func() {
    suite.Run("non-root block", func() {
        _, err := suite.com.IdentityByBlock(nonRootBlockID, realEjectedClusterMember.NodeID)
        suite.Assert().True(model.IsInvalidSignerError(err)) // correctly rejected
    })
    suite.Run("by epoch", func() {
        actual, err := suite.com.IdentityByEpoch(rand.Uint64(), realEjectedClusterMember.NodeID)
        suite.Assert().NoError(err) // BUG: ejected node passes validation
        suite.Assert().Equal(realEjectedClusterMember.IdentitySkeleton, *actual)
    })
})
```

An ejected collection node can exploit this by continuing to send votes after ejection. Each vote passes `IdentityByEpoch` and is counted with the node's original `InitialWeight` toward QC formation in the cluster.

**Root cause references:** [1](#0-0) 

`IdentityByBlock` correctly applies `clusterMemberFilter` (which includes `filter.IsValidCurrentEpochParticipant`): [2](#0-1) 

The `clusterMemberFilter` is constructed to require active participation status: [3](#0-2) 

The test confirming `IdentityByEpoch` accepts ejected members without error: [4](#0-3) 

`IdentityProvider.ByPeerID` contract explicitly warns callers to check ejection status — a warning `IdentityByEpoch` ignores: [5](#0-4) 

`IsValidCurrentEpochParticipant` filter definition (what `IdentityByEpoch` should enforce): [6](#0-5)

### Citations

**File:** consensus/hotstuff/committees/cluster_committee.go (L60-64)
```go
		selection: selection,
		clusterMemberFilter: filter.And[flow.Identity](
			initialClusterMembersSelector,
			filter.IsValidCurrentEpochParticipant,
		),
```

**File:** consensus/hotstuff/committees/cluster_committee.go (L119-122)
```go
	if !c.clusterMemberFilter(identity) {
		return nil, model.NewInvalidSignerErrorf("node %v is not an authorized hotstuff cluster member", nodeID)
	}
	return identity, nil
```

**File:** consensus/hotstuff/committees/cluster_committee.go (L140-146)
```go
func (c *Cluster) IdentityByEpoch(view uint64, participantID flow.Identifier) (*flow.IdentitySkeleton, error) {
	identity, ok := c.clusterMembers.ByNodeID(participantID)
	if !ok {
		return nil, model.NewInvalidSignerErrorf("node %v is not an authorized hotstuff participant", participantID)
	}
	return identity, nil
}
```

**File:** consensus/hotstuff/committees/cluster_committee_test.go (L161-171)
```go
	suite.Run("should return ErrInvalidSigner for existent but ejected cluster member", func() {
		suite.Run("non-root block", func() {
			_, err := suite.com.IdentityByBlock(nonRootBlockID, realEjectedClusterMember.NodeID)
			suite.Assert().True(model.IsInvalidSignerError(err))
		})
		suite.Run("by epoch", func() {
			actual, err := suite.com.IdentityByEpoch(rand.Uint64(), realEjectedClusterMember.NodeID)
			suite.Assert().NoError(err)
			suite.Assert().Equal(realEjectedClusterMember.IdentitySkeleton, *actual)
		})
	})
```

**File:** module/id_provider.go (L33-39)
```go
	// ByPeerID returns the full identity for the node with the given peer ID,
	// where ID is the way the libP2P refers to the node. The function
	// has the same semantics as a map lookup, where the boolean return value is
	// true if and only if Identity has been found, i.e. `Identity` is not nil.
	// Caution: function returns include ejected nodes. Please check the `Ejected`
	// flag in the identity.
	ByPeerID(peer.ID) (*flow.Identity, bool)
```

**File:** model/flow/filter/identity.go (L115-118)
```go
// IsValidCurrentEpochParticipant is an identity filter for members of the
// current epoch in good standing.
// Effective it means that node is an active identity in current epoch and has not been ejected.
var IsValidCurrentEpochParticipant = HasParticipationStatus(flow.EpochParticipationStatusActive)
```
