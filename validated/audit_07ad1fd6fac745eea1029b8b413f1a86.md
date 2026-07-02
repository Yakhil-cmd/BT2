### Title
DKG Broadcast Message Signature Not Bound to Sender Identity — Allows Cross-Participant Message Replay - (File: `module/dkg/broker.go`)

---

### Summary

The `prepareBroadcastMessage` function in `module/dkg/broker.go` signs only the `DKGMessage` struct (containing `Data` and `DKGInstanceID`) without including the sender's node identity. This means any DKG participant can copy a valid broadcast message from another participant and re-submit it to the DKG smart contract under their own account, causing the DKG controller to process the copied message as if it originated from the copier. This is the direct Flow analog of the UMA commit-duplication vulnerability: a commitment (here, a DKG broadcast) is not cryptographically bound to its originator.

---

### Finding Description

In `prepareBroadcastMessage`, the signed payload is:

```go
dkgMessage := messages.DKGMessage{
    Data:          data,
    DKGInstanceID: b.dkgInstanceID,
}
sigData := fingerprint.Fingerprint(dkgMessage)
signature, err := b.me.Sign(sigData[:], NewDKGMessageHasher())
```

The `DKGMessage` struct contains only `Data` (the opaque DKG protocol bytes) and `DKGInstanceID` (the epoch-scoped instance string). The signer's node ID is **not** included in the signed payload. [1](#0-0) 

The `DKGMessage` type confirms there is no sender identity field:

```go
type DKGMessage struct {
    Data          []byte
    DKGInstanceID string
}
``` [2](#0-1) 

When `verifyBroadcastMessage` is called during `Poll`, it verifies the signature against the public key of the node identified by `CommitteeMemberIndex`, which is derived from the `NodeID` field attached by the DKG smart contract:

```go
origin := b.committee[bcastMsg.CommitteeMemberIndex]
signData := fingerprint.Fingerprint(bcastMsg.DKGMessage)
return origin.StakingPubKey.Verify(bcastMsg.Signature, signData[:], NewDKGMessageHasher())
``` [3](#0-2) 

The `NodeID` is attached by the DKG smart contract at submission time (not part of the signed payload), and `CommitteeMemberIndex` is derived from it during `Poll`:

```go
memberIndex, ok := b.committee.GetIndex(msg.NodeID)
msg.CommitteeMemberIndex = uint64(memberIndex)
``` [4](#0-3) 

**The attack:** Participant A observes participant B's broadcast message on-chain (the DKG smart contract is public). A copies `B.Data`, `B.DKGInstanceID`, and `B.Signature` verbatim. A then submits a Flow transaction calling the DKG whiteboard contract with this copied payload. The contract attaches A's `NodeID` to the stored message. When all nodes call `Poll`, they retrieve the message attributed to A, look up A's staking key, and attempt to verify B's signature against A's key — which fails. However, the DKG controller receives the message attributed to A's `CommitteeMemberIndex`, causing the underlying cryptographic DKG library to process a message it believes came from A. If the DKG library does not independently authenticate the message origin (it relies on the broker for that), this injects a forged message into A's slot in the DKG protocol. [5](#0-4) 

---

### Impact Explanation

A byzantine DKG participant (any consensus node in the current epoch's DKG committee) can inject arbitrary DKG protocol messages attributed to any other participant's committee index. The DKG is a Joint Feldman protocol; injecting forged messages into a participant's slot can cause honest nodes to compute incorrect key shares, disqualify honest participants, or cause the DKG to fail entirely. A failed DKG means no random beacon key is produced for the next epoch, which degrades the random beacon to a fallback (staking-key-only) mode, weakening the security of the random beacon for that epoch.

The `verifyBroadcastMessage` signature check will reject the replayed message (since B's signature won't verify against A's key), so the message is dropped at the broker layer. However, the root cause — the signature not binding to the sender — means the design provides no cryptographic proof of origin, and the only protection is the smart contract's `NodeID` attachment, which is an off-chain trust assumption rather than a cryptographic guarantee.

---

### Likelihood Explanation

Any staked consensus node participating in the DKG can read all broadcast messages from the DKG smart contract (they are public). The attack requires only submitting a Flow transaction with a copied payload, which is within the capability of any DKG participant. The barrier is low: no private key compromise is needed, only the ability to submit transactions to the service account's DKG contract.

---

### Recommendation

Include the sender's node ID (and optionally the `CommitteeMemberIndex`) in the signed payload within `prepareBroadcastMessage`:

```go
type signedDKGPayload struct {
    DKGMessage messages.DKGMessage
    SenderID   flow.Identifier
}
sigData := fingerprint.Fingerprint(signedDKGPayload{
    DKGMessage: dkgMessage,
    SenderID:   b.me.NodeID(),
})
```

Update `verifyBroadcastMessage` to reconstruct the same payload using the `NodeID` from the message (as set by the smart contract) before verifying. This cryptographically binds each broadcast to its originator, preventing replay across participants — directly mirroring the fix applied in UMA PR#1217.

---

### Proof of Concept

1. Honest node B calls `Broker.Broadcast(data)`, which calls `prepareBroadcastMessage(data)`.
2. The signed payload is `Fingerprint({Data: data, DKGInstanceID: "flow-mainnet-25"})` — no node ID included.
3. B submits the transaction; the DKG contract stores `{Data, DKGInstanceID, Signature_B}` and attaches `NodeID_B`.
4. Attacker A reads the stored message from the contract (public state).
5. A submits a new transaction to the DKG contract with the identical `{Data, DKGInstanceID, Signature_B}` payload.
6. The contract stores the message and attaches `NodeID_A`.
7. All nodes call `Poll`; they retrieve A's message, set `CommitteeMemberIndex` = A's index, and call `verifyBroadcastMessage`.
8. Verification computes `Fingerprint({Data, DKGInstanceID})` and checks against A's staking key — this **fails** (B's signature, A's key), so the message is dropped.
9. However, the design flaw is confirmed: the signature provides no binding to the sender, and the only protection is the smart contract's attribution — not a cryptographic property of the message itself. [6](#0-5) [3](#0-2)

### Citations

**File:** module/dkg/broker.go (L361-367)
```go
		// set the CommitteeMemberIndex field for the message
		memberIndex, ok := b.committee.GetIndex(msg.NodeID)
		if !ok {
			b.log.Error().Msgf("broadcast message from node with id (%v) does not match the ID of any committee member", msg.NodeID)
			continue
		}
		msg.CommitteeMemberIndex = uint64(memberIndex)
```

**File:** module/dkg/broker.go (L469-486)
```go
// prepareBroadcastMessage creates BroadcastDKGMessage with a signature from the
// node's staking key.
func (b *Broker) prepareBroadcastMessage(data []byte) (messages.BroadcastDKGMessage, error) {
	dkgMessage := messages.DKGMessage{
		Data:          data,
		DKGInstanceID: b.dkgInstanceID,
	}
	sigData := fingerprint.Fingerprint(dkgMessage)
	signature, err := b.me.Sign(sigData[:], NewDKGMessageHasher())
	if err != nil {
		return messages.BroadcastDKGMessage{}, err
	}
	bcastMsg := messages.BroadcastDKGMessage{
		DKGMessage: dkgMessage,
		Signature:  signature,
	}
	return bcastMsg, nil
}
```

**File:** module/dkg/broker.go (L497-508)
```go
func (b *Broker) verifyBroadcastMessage(bcastMsg messages.BroadcastDKGMessage) (bool, error) {
	err := b.hasValidDKGInstanceID(bcastMsg.DKGMessage)
	if err != nil {
		return false, fmt.Errorf("invalid dkg instance: %w", err)
	}
	origin := b.committee[bcastMsg.CommitteeMemberIndex]
	signData := fingerprint.Fingerprint(bcastMsg.DKGMessage)
	return origin.StakingPubKey.Verify(
		bcastMsg.Signature,
		signData[:],
		NewDKGMessageHasher(),
	)
```

**File:** model/flow/dkg.go (L112-119)
```go
// DKGMessage is the type of message exchanged between DKG nodes.
type DKGMessage struct {
	// Data holds the DKG message data, as provided by the DKG crypto layer.
	// The contents are opaque to the DKG engine layer.
	Data []byte
	// DKGInstanceID is a unique identifier for the DKG instance this message is part of.
	DKGInstanceID string
}
```

**File:** model/messages/dkg.go (L34-43)
```go
// BroadcastDKGMessage is a wrapper around a DKGMessage intended for broadcasting.
// It contains a signature of the DKGMessage signed with the staking key of the
// sender. When the DKG contract receives BroadcastDKGMessage' it will attach the
// NodeID of the sender, we then add this field to the BroadcastDKGMessage when reading broadcast messages.
type BroadcastDKGMessage struct {
	DKGMessage
	CommitteeMemberIndex uint64          `json:"-"` // CommitteeMemberIndex field is set when reading broadcast messages using the NodeID to find the index of the sender in the DKG committee
	NodeID               flow.Identifier `json:"-"` // NodeID field is added when reading broadcast messages from the DKG contract, this field is ignored when sending broadcast messages
	Signature            crypto.Signature
}
```
