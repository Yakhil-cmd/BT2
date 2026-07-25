### Title
Unauthenticated Bridge Peer Can Inject Arbitrary RPC Calls into Main Bridge's RPC Server via Unrestricted `handleCallMsg` — (File: node/sc/main_bridge_handler.go)

### Summary

`MainBridgeHandler.handleCallMsg` accepts a `ServiceChainCall` P2P message from any connected bridge peer and writes its raw payload directly to the main bridge's internal RPC server pipe with no content validation, method allowlist, or per-call authorization check. The bridge P2P handshake only verifies `networkId` and `chainID` — both public values — so any node that can reach the bridge P2P port can become a peer and inject arbitrary JSON-RPC calls into the main chain's RPC server.

### Finding Description

**Root cause — `handleCallMsg` (node/sc/main_bridge_handler.go:86–102)**

```go
func (mbh *MainBridgeHandler) handleCallMsg(p BridgePeer, msg p2p.Msg) error {
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    if err != nil { ... }
    // Write to RPC server pipe — no method filter, no caller check
    _, err = mbh.mainbridge.rpcConn.Write(data)
    return err
}
```

`HandleSubMsg` dispatches every `ServiceChainCall` message to this function without any identity or content check beyond what the P2P layer already did. [1](#0-0) 

**Handshake provides no real authentication**

The `Handshake` in `baseBridgePeer` only exchanges `ProtocolVersion`, `NetworkId`, `TD`, `CurrentBlock`, and `ChainID`. [2](#0-1)  Both `networkId` and `chainID` are public values for any deployed chain. There is no cryptographic proof of identity, no whitelist of allowed peer addresses, and no per-peer capability restriction.

**Arbitrary data reaches the RPC server**

`rpcConn` is the write end of a pipe whose read end is served by the main chain's RPC server. Whatever bytes `handleCallMsg` writes are processed as a legitimate JSON-RPC request. The SubBridge side confirms the symmetric design: it reads from its own `rpcConn` and forwards data to peers via `SendRequestRPC`. [3](#0-2) 

**Analogy to the external report**

The external `fallback()` bug: any caller can route a call to an installed handler, bypassing the entrypoint/signature-validation path. Here: any bridge peer can route an arbitrary JSON-RPC payload to the main chain's RPC server, bypassing the normal HTTP/WS authentication layer that would otherwise gate those methods.

### Impact Explanation

The concrete impact depends on which RPC namespaces are registered on the server instance that owns the pipe. If the server exposes `admin_*` (peer management, node control), `personal_*` (account unlock, key export), `miner_*`, or `debug_*` methods, a malicious bridge peer can:

- Call `admin_addPeer` / `admin_removePeer` to manipulate the validator/peer topology (bridge, governance, validator privilege escalation).
- Call `personal_unlockAccount` to unlock a key held by the node, enabling unauthorized KAIA transfers.
- Call `miner_setEtherbase` / `miner_start` to redirect block rewards (unauthorized reward distribution).

Even in a read-only configuration the attacker can enumerate internal state (nonces, balances, pending transactions) that is not intended to be public.

### Likelihood Explanation

The bridge P2P port is a separate listener from the main chain P2P port and is not intended to be publicly reachable. However:

- Operators who expose the bridge port on a public interface (misconfiguration, cloud security-group error) are immediately vulnerable.
- The only barrier is TCP reachability plus knowledge of `networkId`/`chainID`, both of which are public for any live chain.
- There is no rate-limit, no IP allowlist, and no cryptographic peer authentication in the bridge handshake path.

Likelihood is **medium** given the deployment assumption, but the attack requires zero on-chain privileges.

### Recommendation

1. **Method allowlist**: Before writing to `rpcConn`, parse the JSON-RPC method name and reject any call not in an explicit allowlist of read-only methods needed by the service chain (e.g., `kaia_getTransactionCount`, `kaia_gasPrice`).
2. **Peer authentication**: Extend the bridge handshake to require a cryptographic proof of identity (e.g., sign a challenge with the operator's key) and maintain a whitelist of authorised peer public keys.
3. **Separate RPC server**: Expose a dedicated, restricted RPC server instance to the bridge pipe rather than the full node RPC server, so the blast radius is bounded by design.

### Proof of Concept

1. Identify the main bridge P2P port (default `50505` or operator-configured).
2. Connect with a standard Kaia P2P client, completing the bridge handshake with the target chain's `networkId` and `chainID`.
3. Send a `ServiceChainCall` (msg code `0x11`) P2P message whose payload is the RLP-encoded bytes of:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"personal_unlockAccount","params":["0x<target>","",0]}
   ```
4. `handleCallMsg` decodes the bytes and writes them verbatim to `mbh.mainbridge.rpcConn`. [4](#0-3) 
5. The main chain RPC server processes the request as if it arrived from a trusted local client; if `personal` is enabled, the account is unlocked and subsequent KAIA transfers can be submitted by the attacker. [1](#0-0) [5](#0-4) [6](#0-5)

### Citations

**File:** node/sc/main_bridge_handler.go (L48-84)
```go
func (mbh *MainBridgeHandler) HandleSubMsg(p BridgePeer, msg p2p.Msg) error {
	logger.Trace("mainbridge handle sub message", "msg.Code", msg.Code)

	// Handle the message depending on its contents
	switch msg.Code {
	case ServiceChainCall:
		if err := mbh.handleCallMsg(p, msg); err != nil {
			return err
		}
		return nil
	case StatusMsg:
		return nil
	case ServiceChainTxsMsg:
		logger.Trace("received ServiceChainTxsMsg")
		// TODO-Kaia how to check acceptTxs
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		//if atomic.LoadUint32(&pm.acceptTxs) == 0 {
		//	break
		//}
		if err := mbh.handleServiceChainTxDataMsg(p, msg); err != nil {
			return err
		}
	case ServiceChainParentChainInfoRequestMsg:
		logger.Debug("received ServiceChainParentChainInfoRequestMsg")
		if err := mbh.handleServiceChainParentChainInfoRequestMsg(p, msg); err != nil {
			return err
		}
	case ServiceChainReceiptRequestMsg:
		logger.Debug("received ServiceChainReceiptRequestMsg")
		if err := mbh.handleServiceChainReceiptRequestMsg(p, msg); err != nil {
			return err
		}
	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}
```

**File:** node/sc/main_bridge_handler.go (L86-102)
```go
func (mbh *MainBridgeHandler) handleCallMsg(p BridgePeer, msg p2p.Msg) error {
	logger.Trace("mainbridge writes the rpc call message to rpc server", "msg.Size", msg.Size, "msg", msg)
	data := make([]byte, msg.Size)
	err := msg.Decode(&data)
	if err != nil {
		logger.Error("error in mainbridge message handler", "err", err)
		return err
	}

	// Write to RPC server pipe
	_, err = mbh.mainbridge.rpcConn.Write(data)
	if err != nil {
		logger.Error("failed to write to the rpc server pipe", "err", err)
		return err
	}
	return nil
}
```

**File:** node/sc/bridgepeer.go (L265-303)
```go
// Handshake executes the Kaia protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *baseBridgePeer) Handshake(network uint64, chainID, td *big.Int, head common.Hash) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		errc <- p2p.Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			ChainID:         chainID,
		})
	}()
	go func() {
		e := p.readStatus(network, &status)
		if e != nil {
			errc <- e
			return
		}
		errc <- e
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for range 2 {
		select {
		case err := <-errc:
			if err != nil {
				return err
			}
		case <-timeout.C:
			return p2p.DiscReadTimeout
		}
	}
	p.td, p.head, p.chainID = status.TD, status.CurrentBlock, status.ChainID
	return nil
}
```

**File:** node/sc/subbridge.go (L240-276)
```go
func (sb *SubBridge) SetRPCConn(conn net.Conn) {
	sb.rpcConn = conn

	go func() {
		for {
			data := make([]byte, rpcBufferSize)
			rlen, err := sb.rpcConn.Read(data)
			if err != nil {
				if err == io.EOF {
					logger.Trace("EOF from the rpc pipe")
					time.Sleep(100 * time.Millisecond)
					continue
				} else {
					// If no one closes the pipe, this situation should not happen.
					logger.Error("failed to read from the rpc pipe", "err", err, "rlen", rlen)
					return
				}
			}
			sb.rpcSendCh <- data[:rlen]
		}
	}()
}

func (sb *SubBridge) SendRPCData(data []byte) error {
	peers := sb.BridgePeerSet().peers
	logger.Trace("send rpc message from the subbridge", "len", len(data), "peers", len(peers))
	for _, peer := range peers {
		err := peer.SendRequestRPC(data)
		if err != nil {
			logger.Error("SendRPCData Error", "err", err)
		}
		return err
	}
	logger.Trace("send rpc message from the subbridge, done")

	return nil
}
```

**File:** node/sc/mainbridge.go (L361-399)
```go
func (mb *MainBridge) handle(p BridgePeer) error {
	// Ignore maxPeers if this is a trusted peer
	if mb.peers.Len() >= mb.maxPeers && !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
		return p2p.DiscTooManyPeers
	}
	p.GetP2PPeer().Log().Debug("Kaia peer connected", "name", p.GetP2PPeer().Name())

	// Execute the handshake
	var (
		head   = mb.blockchain.CurrentHeader()
		hash   = head.Hash()
		number = head.Number.Uint64()
		td     = mb.blockchain.GetTd(hash, number)
	)

	err := p.Handshake(mb.networkId, mb.getChainID(), td, hash)
	if err != nil {
		p.GetP2PPeer().Log().Debug("Kaia peer handshake failed", "err", err)
		return err
	}

	// Register the peer locally
	if err := mb.peers.Register(p); err != nil {
		// if starting node with unlock account, can't register peer until finish unlock
		p.GetP2PPeer().Log().Info("Kaia peer registration failed", "err", err)
		return err
	}
	defer mb.removePeer(p.GetID())

	p.GetP2PPeer().Log().Info("Added a P2P Peer", "peerID", p.GetP2PPeerID())

	// main loop. handle incoming messages.
	for {
		if err := mb.handleMsg(p); err != nil {
			p.GetP2PPeer().Log().Debug("Klaytn message handling failed", "err", err)
			return err
		}
	}
}
```
