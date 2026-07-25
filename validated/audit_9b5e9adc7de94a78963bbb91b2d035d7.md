### Title
Unauthenticated Bridge Peer Can Inject Arbitrary JSON-RPC Calls Into Main Bridge's Internal RPC Server - (File: `node/sc/main_bridge_handler.go`)

---

### Summary

The `MainBridge` service chain handler accepts `ServiceChainCall` P2P messages from any connected bridge peer and writes their raw bytes directly into the main bridge's internal RPC server pipe without any validation of the RPC method, caller identity, or content. Because the bridge peer handshake only checks network ID and chain ID (both public values), any node that can reach the main bridge's P2P port can inject arbitrary JSON-RPC requests into the internal RPC server. The symmetric path on the sub-bridge side (`HandleMainMsg`) allows any connected main-bridge peer to inject arbitrary RPC responses into the sub-bridge's RPC client, which the `RemoteBackend` uses to drive bridge value-transfer decisions.

---

### Finding Description

**Main bridge side — arbitrary RPC call injection:**

In `NewMainBridge` (`node/sc/mainbridge.go`, lines 153–156), an internal RPC server is created and connected to a `net.Pipe()`:

```go
mb.rpcServer = rpc.NewServer()
p1, p2 := net.Pipe()
mb.rpcConn = p1
go mb.rpcServer.ServeCodec(rpc.NewCodec(p2), 0)
``` [1](#0-0) 

`handleCallMsg` in `node/sc/main_bridge_handler.go` (lines 86–102) receives a `ServiceChainCall` P2P message, decodes the raw bytes, and writes them verbatim to `rpcConn` — the live end of that pipe — with no validation of the JSON-RPC method name, parameters, or the identity of the sending peer:

```go
func (mbh *MainBridgeHandler) handleCallMsg(p BridgePeer, msg p2p.Msg) error {
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    ...
    _, err = mbh.mainbridge.rpcConn.Write(data)   // ← raw bytes from peer go straight to RPC server
    ...
}
``` [2](#0-1) 

This is dispatched from `HandleSubMsg` for every `ServiceChainCall` message received from any bridge peer: [3](#0-2) 

**Sub-bridge side — arbitrary RPC response injection:**

The symmetric path in `HandleMainMsg` (`node/sc/sub_bridge_handler.go`, lines 233–245) writes any `ServiceChainResponse` message from any connected main-bridge peer directly into the sub-bridge's RPC client pipe:

```go
case ServiceChainResponse:
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    ...
    _, err = sbh.subbridge.rpcConn.Write(data)   // ← raw bytes from peer go straight to RPC client
``` [4](#0-3) 

The sub-bridge's `RemoteBackend` is an `rpc.Client` whose transport is this same pipe (`NewRpcClientP2P`, `node/sc/remote_backend.go`, lines 47–55). It uses this client to query the parent chain for nonces, balances, and to submit handle transactions: [5](#0-4) 

**Why the peer is not authenticated:**

The bridge peer handshake (`baseBridgePeer.Handshake`, `node/sc/bridgepeer.go`, lines 267–302) only exchanges network ID, chain ID, TD, and head hash — all public values. There is no check that the connecting node is an authorized service-chain operator: [6](#0-5) 

The `handle` function in `mainbridge.go` only enforces a peer count limit and the protocol handshake; it does not verify the peer's node ID against any allowlist: [7](#0-6) 

---

### Impact Explanation

**Main bridge path:** Any node that can reach the main bridge's P2P port and knows the public network/chain ID can connect as a bridge peer and send `ServiceChainCall` messages containing arbitrary JSON-RPC payloads. These are executed by the main bridge's internal `rpc.Server`. Depending on which APIs are registered on that server (the registration code was not fully traced in available index), this can include `kaia_sendRawTransaction`, which would allow the attacker to submit arbitrary (but still signature-valid) transactions to the parent chain's tx pool, consuming the bridge operator's nonce or flooding the pool with anchoring-type transactions.

**Sub-bridge path (higher severity):** Any node that can connect to the sub-bridge as a main-bridge peer can inject crafted `ServiceChainResponse` messages. The sub-bridge's `RemoteBackend` trusts these responses unconditionally. A malicious peer can return a falsified nonce for the bridge operator account, causing the sub-bridge to reuse or skip nonces on handle transactions, or return a falsified balance/receipt, causing the bridge to incorrectly believe a value-transfer handle transaction was confirmed when it was not — leading to double-handle or missed-handle of KAIA/ERC20/ERC721 bridge transfers. [8](#0-7) 

---

### Likelihood Explanation

The main bridge P2P port is reachable by any node on the network. The only prerequisite is knowing the network ID and chain ID, both of which are public. No privileged key or majority-validator collusion is required. An attacker simply connects as a bridge peer (standard RLPx + bridge handshake) and sends a crafted `ServiceChainCall` or `ServiceChainResponse` message.

---

### Recommendation

1. **Authenticate bridge peers against an allowlist.** After the handshake, verify the connecting peer's node ID or address against a configured set of authorized service-chain nodes before accepting `ServiceChainCall`/`ServiceChainResponse` messages.
2. **Validate the JSON-RPC method name** in `handleCallMsg` against an explicit allowlist of methods the sub-bridge is permitted to invoke (e.g., only `kaia_getTransactionCount`, `kaia_sendRawTransaction`, `kaia_getTransactionReceipt`).
3. **Validate RPC response structure** in `HandleMainMsg` before writing to the RPC client pipe, rejecting responses that do not correspond to an outstanding request ID.

---

### Proof of Concept

1. Attacker runs a node and connects to the main bridge's P2P port.
2. Attacker completes the bridge handshake with the correct `networkId` and `chainID` (public values).
3. Attacker sends a P2P message with code `ServiceChainCall` containing the JSON-RPC payload:
   ```json
   {"jsonrpc":"2.0","id":1,"method":"kaia_sendRawTransaction","params":["0x<crafted_raw_tx>"]}
   ```
4. `handleCallMsg` decodes the bytes and writes them to `mbh.mainbridge.rpcConn` with no further checks.
5. The internal `rpc.Server` processes the call and the response is forwarded back to the attacker.

For the sub-bridge injection path:
1. Attacker connects to the sub-bridge as a main-bridge peer.
2. Attacker sends a `ServiceChainResponse` message containing a crafted JSON-RPC response with a falsified nonce value for the bridge operator address.
3. `HandleMainMsg` writes the bytes to `sbh.subbridge.rpcConn`.
4. The sub-bridge's `RemoteBackend` RPC client reads the falsified nonce and uses it for the next handle transaction, causing a nonce collision or skip that breaks the bridge's value-transfer accounting. [2](#0-1) [9](#0-8) [10](#0-9)

### Citations

**File:** node/sc/mainbridge.go (L153-179)
```go
	mb.rpcServer = rpc.NewServer()
	p1, p2 := net.Pipe()
	mb.rpcConn = p1
	go mb.rpcServer.ServeCodec(rpc.NewCodec(p2), 0)

	go func() {
		for {
			data := make([]byte, rpcBufferSize)
			rlen, err := mb.rpcConn.Read(data)
			if err != nil {
				if err == io.EOF {
					logger.Trace("EOF from the rpc server pipe")
					time.Sleep(100 * time.Millisecond)
					continue
				} else {
					// If no one closes the pipe, this situation should not happen.
					logger.Error("failed to read from the rpc pipe", "err", err, "rlen", rlen)
					return
				}
			}
			logger.Trace("mainbridge message from rpc server pipe", "rlen", rlen)
			err = mb.SendRPCResponseData(data[:rlen])
			if err != nil {
				logger.Error("failed to send response data from RPC server pipe", err)
			}
		}
	}()
```

**File:** node/sc/mainbridge.go (L361-398)
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
```

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

**File:** node/sc/sub_bridge_handler.go (L230-268)
```go
func (sbh *SubBridgeHandler) HandleMainMsg(p BridgePeer, msg p2p.Msg) error {
	// Handle the message depending on its contents
	switch msg.Code {
	case ServiceChainResponse:
		logger.Trace("received rpc ServiceChainResponse")
		data := make([]byte, msg.Size)
		err := msg.Decode(&data)
		if err != nil {
			logger.Error("failed to decode the p2p ServiceChainResponse message", "err", err)
			return nil
		}
		logger.Trace("send rpc response to the rpc client")
		_, err = sbh.subbridge.rpcConn.Write(data)
		if err != nil {
			return err
		}
		return nil
	case StatusMsg:
		return nil
	case ServiceChainParentChainInfoResponseMsg:
		logger.Debug("received ServiceChainParentChainInfoResponseMsg")
		if err := sbh.handleParentChainInfoResponseMsg(p, msg); err != nil {
			return err
		}

	case ServiceChainReceiptResponseMsg:
		logger.Debug("received ServiceChainReceiptResponseMsg")
		if err := sbh.handleParentChainReceiptResponseMsg(p, msg); err != nil {
			return err
		}
	case ServiceChainInvalidTxResponseMsg:
		logger.Debug("received ServiceChainInvalidTxResponseMsg")
		if err := sbh.handleParentChainInvalidTxResponseMsg(msg); err != nil {
			return err
		}
	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
```

**File:** node/sc/remote_backend.go (L47-55)
```go
func NewRpcClientP2P(sb *SubBridge) *rpc.Client {
	initctx := context.Background()
	c, _ := rpc.NewClient(initctx, func(ctx context.Context) (rpc.ServerCodec, error) {
		p1, p2 := net.Pipe()
		sb.SetRPCConn(p1)
		return rpc.NewCodec(p2), nil
	})
	return c
}
```

**File:** node/sc/bridgepeer.go (L267-302)
```go
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
```

**File:** node/sc/bridge_manager.go (L292-360)
```go
// handleRequestValueTransferEvent handles the given request value transfer event.
func (bi *BridgeInfo) handleRequestValueTransferEvent(ev IRequestValueTransferEvent) error {
	var (
		tokenType                         = ev.GetTokenType()
		tokenAddr, from, to, contractAddr = ev.GetTokenAddress(), ev.GetFrom(), ev.GetTo(), ev.GetRaw().Address
		txHash                            = ev.GetRaw().TxHash
		valueOrTokenId                    = ev.GetValueOrTokenId()
		requestNonce, blkNumber           = ev.GetRequestNonce(), ev.GetRaw().BlockNumber
		extraData                         = ev.GetExtraData()
	)

	ctpartTokenAddr := bi.GetCounterPartToken(tokenAddr)
	// TODO-Kaia-Servicechain Add counterpart token address in requestValueTransferEvent
	if tokenType != KAIA && ctpartTokenAddr == (common.Address{}) {
		logger.Warn("Unregistered counter part token address.", "addr", ctpartTokenAddr.Hex())
		ctTokenAddr, err := bi.counterpartBridge.RegisteredTokens(nil, tokenAddr)
		if err != nil {
			return err
		}
		if ctTokenAddr == (common.Address{}) {
			return errors.New("can't get counterpart token from bridge")
		}
		if err := bi.RegisterToken(tokenAddr, ctTokenAddr); err != nil {
			return err
		}
		ctpartTokenAddr = ctTokenAddr
		logger.Info("Register counter part token address.", "addr", ctpartTokenAddr.Hex(), "cpAddr", ctTokenAddr.Hex())
	}

	bridgeAcc := bi.account

	bridgeAcc.Lock()
	defer bridgeAcc.UnLock()

	auth := bridgeAcc.GenerateTransactOpts()

	var handleTx *types.Transaction
	var err error

	switch tokenType {
	case KAIA:
		handleTx, err = bi.bridge.HandleKLAYTransfer(auth, txHash, from, to, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[KAIA], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC20:
		handleTx, err = bi.bridge.HandleERC20Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC20], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	case ERC721:
		uri := GetURI(ev)
		handleTx, err = bi.bridge.HandleERC721Transfer(auth, txHash, from, to, ctpartTokenAddr, valueOrTokenId, requestNonce, blkNumber, uri, extraData)
		if err != nil {
			return err
		}
		handleValueTransferLog(bi.onChildChain, handleVTmethods[ERC721], handleTx.Hash().String(), requestNonce, from, to, valueOrTokenId)
	default:
		logger.Error("Got Unknown Token Type ReceivedEvent", "bridge", contractAddr, "nonce", requestNonce, "from", from)
		return nil
	}

	bridgeAcc.IncNonce()

	bi.bridgeDB.WriteHandleTxHashFromRequestTxHash(txHash, handleTx.Hash())
	return nil
}
```
