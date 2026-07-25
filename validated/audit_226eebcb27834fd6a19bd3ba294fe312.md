The code at lines 1290-1328 contains two separate checks. Reading them together reveals a clear logic inversion:

The logic inversion is real and unambiguous. Here is the full analysis:

---

### Title
Inverted Trusted-Peer Guard in `multiChannelPeer.Handle` Disconnects Trusted Peers Instead of Protecting Them — (`node/cn/peer.go`)

### Summary

`multiChannelPeer.Handle` contains two peer-count/snapSync rejection guards. The first (line 1291) is correct. The second (lines 1323–1328) carries the same comment — *"Ignore maxPeers if this is a trusted peer"* — but the condition is inverted: it applies the rejection **only** to trusted peers and silently skips untrusted peers. An attacker who fills `pm.peers` to `maxPeers` via public P2P connections causes every subsequent trusted-peer connection attempt to be rejected with `DiscTooManyPeers`, while untrusted peers that already passed the first guard proceed unimpeded.

### Finding Description

**Check 1 — correct (line 1291):**
```go
// Ignore maxPeers if this is a trusted peer
if pm.peers.Len() >= pm.maxPeers && !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
    return p2p.DiscTooManyPeers
}
```
Rejects untrusted peers when the table is full; trusted peers bypass it. [1](#0-0) 

**Check 2 — inverted (lines 1323–1328):**
```go
// Ignore maxPeers if this is a trusted peer
if p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
    if reject || pm.peers.Len() >= pm.maxPeers {
        return p2p.DiscTooManyPeers
    }
}
```
The outer condition is `if Trusted` instead of `if !Trusted`. The rejection fires **exclusively** for trusted peers; untrusted peers that reached this point are never checked. [2](#0-1) 

The `reject` flag is set to `true` when `snapSync == 1` and the non-snap peer ratio exceeds the threshold. [3](#0-2) 

**Combined per-peer behavior:**

| Peer type | Check 1 (line 1291) | Check 2 (line 1325) | Net result when table full |
|---|---|---|---|
| Untrusted | Rejected if full | Never evaluated | Rejected at check 1 |
| Trusted | Always passes | Rejected if full **or** `reject=true` | Rejected at check 2 — wrong |

### Impact Explanation

Trusted peers in Kaia's P2P layer are explicitly operator-configured nodes (e.g., co-validators, boot nodes) that are supposed to bypass peer-count limits. Because the guard is inverted, a trusted validator peer that correctly passes check 1 is then unconditionally rejected by check 2 whenever the table is at capacity or `snapSync` reject is active. This prevents trusted validator nodes from maintaining connections to each other, which can cause consensus divergence: a validator isolated from its trusted peers cannot participate in IBFT rounds, leading to missed blocks or a stalled chain.

### Likelihood Explanation

The attacker only needs to open `maxPeers` inbound P2P connections to the target node — a standard public P2P operation requiring no credentials, keys, or governance access. Default `maxPeers` values (25–50) are reachable with modest resources. The snapSync path (`reject=true`) is an additional trigger that requires no attacker action beyond the node being in snap-sync mode.

### Recommendation

Invert the outer condition in the second guard to match the first and the comment:

```go
// Ignore maxPeers if this is a trusted peer
if !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
    if reject || pm.peers.Len() >= pm.maxPeers {
        return p2p.DiscTooManyPeers
    }
}
```

### Proof of Concept

1. Set `pm.maxPeers = 5` and register 5 untrusted peers so `pm.peers.Len() == 5`.
2. Set `pm.snapSync = 1`.
3. Call `Handle` with a peer whose `Trusted = true`.
4. Line 1291: `5 >= 5 && !true` → `false` → peer passes (correct).
5. Line 1325: `Trusted == true` → enter block; `pm.peers.Len() >= pm.maxPeers` → `true` → return `DiscTooManyPeers`.
6. Assert: `Handle` returns `DiscTooManyPeers` for the trusted peer — the invariant is violated. [4](#0-3)

### Citations

**File:** node/cn/peer.go (L1290-1328)
```go
	// Ignore maxPeers if this is a trusted peer
	if pm.peers.Len() >= pm.maxPeers && !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
		return p2p.DiscTooManyPeers
	}
	p.GetP2PPeer().Log().Debug("Kaia peer connected", "name", p.GetP2PPeer().Name())

	pm.peerWg.Add(1)
	defer pm.peerWg.Done()

	// Execute the handshake
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = pm.blockchain.GetTd(hash, number)
	)

	if err := p.Handshake(pm.networkId, pm.getChainID(), td, hash, genesis.Hash()); err != nil {
		p.GetP2PPeer().Log().Debug("Kaia peer handshake failed", "err", err)
		return err
	}
	reject := false
	if atomic.LoadUint32(&pm.snapSync) == 1 {
		if snap == nil {
			// If we are running snap-sync, we want to reserve roughly half the peer
			// slots for peers supporting the snap protocol.
			// The logic here is; we only allow up to 5 more non-snap peers than snap-peers.
			if all, snp := pm.peers.Len(), pm.peers.SnapLen(); all-snp > snp+5 {
				reject = true
			}
		}
	}
	// Ignore maxPeers if this is a trusted peer
	if p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
		if reject || pm.peers.Len() >= pm.maxPeers {
			return p2p.DiscTooManyPeers
		}
	}
```
