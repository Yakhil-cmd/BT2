### Title
Unauthenticated Bridge Peer Can Inject Forged JSON-RPC Responses via `ServiceChainResponse`, Corrupting SubBridge `remoteBackend` Nonce and Contract State — (`node/sc/sub_bridge_handler.go`)

---

### Summary

The `HandleMainMsg` function in `sub_bridge_handler.go` accepts `ServiceChainResponse` P2P messages and writes their raw bytes directly into `sbh.subbridge.rpcConn` with zero validation of response ID, method, or content. Because `rpcConn` is one end of a `net.Pipe()` whose other end is the `rpc.Client` used by `RemoteBackend`, any bridge peer that can send a `ServiceChainResponse` message can inject arbitrary JSON-RPC responses into the SubBridge's RPC client. `RemoteBackend` exposes `PendingNonceAt` (`kaia_getTransactionCount`), `BalanceAt`, `CallContract`, and other methods that drive bridge contract transaction construction. A forged nonce or balance corrupts bridge transaction sequencing on the parent chain.

---

### Finding Description

**The RPC pipe architecture**

`NewRpcClientP2P` in `remote_backend.go` creates a `net.Pipe()` pair:

```
p1 ←→ p2
```

`p1` is stored as `sb.rpcConn`; `p2` is wrapped in `rpc.NewCodec` and handed to the `rpc.Client`. [1](#0-0) 

`SetRPCConn` starts a goroutine that reads outgoing RPC requests from `p1` and forwards them as `ServiceChainCall` P2P messages to the MainBridge peer. [2](#0-1) 

When the MainBridge responds, it sends a `ServiceChainResponse` P2P message. `HandleMainMsg` receives it and writes the raw bytes back into `rpcConn` (p1), making them readable by the `rpc.Client` on p2:

```go
case ServiceChainResponse:
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    ...
    _, err = sbh.subbridge.rpcConn.Write(data)
```

There is no check on response ID, method name, or content. [3](#0-2) 

**What the RPC client is used for**

`RemoteBackend.PendingNonceAt` calls `kaia_getTransactionCount` via this same `rpcClient`. The returned nonce is used by `bind.TransactOpts` when the bridge manager constructs parent-chain bridge contract transactions (value transfers, operator calls). [4](#0-3) 

`BalanceAt` (`kaia_getBalance`), `CallContract` (`kaia_call`), `TransactionReceipt`, and `FilterLogs` all flow through the same pipe and are equally forgeable. [5](#0-4) 

**Peer authentication is absent**

The SubBridge's bridge P2P `handle` function performs only a protocol handshake that checks network ID and chain ID — both public values. There is no cryptographic authentication of peer identity. Any node that knows these values can connect and send `ServiceChainResponse` messages. [6](#0-5) 

`RegisterNewPeer` adds a further chain-ID equality check, but this is also trivially satisfied by an attacker who knows the configured parent chain ID. [7](#0-6) 

**Attack mechanics**

The Go `rpc.Client` matches responses to pending calls by JSON-RPC `id`. IDs are sequential integers (1, 2, 3, …). If the attacker is the only connected bridge peer (they connected before the legitimate MainBridge, or the legitimate peer is unavailable), they receive every `ServiceChainCall` message, can read the `id` field from the JSON payload, and can reply with a `ServiceChainResponse` carrying a crafted result before any legitimate response arrives. Even without being the sole peer, the attacker can race or flood with guessed IDs.

---

### Impact Explanation

- **Nonce corruption**: A forged `kaia_getTransactionCount` response causes `PendingNonceAt` to return an attacker-chosen value. Bridge contract transactions (value transfers, operator calls) are then signed with the wrong nonce, causing them to be rejected by the parent chain or to collide with existing transactions. This stalls or permanently disrupts the bridge's ability to settle cross-chain transfers.
- **Balance/state spoofing**: Forged `kaia_getBalance` or `kaia_call` responses corrupt the bridge manager's view of parent-chain contract state, potentially causing it to approve or reject value transfers based on false data.
- **Durable bridge disruption**: Because the bridge's nonce state is persisted and used for subsequent transactions, a single successful injection can cause a lasting nonce gap that requires manual operator intervention to repair.

---

### Likelihood Explanation

The bridge P2P server is a separate listener (distinct from the main Kaia P2P port) but is reachable by any node that knows the network ID and chain ID — both of which are public. An attacker who can reach the port and connect before or instead of the legitimate MainBridge peer has full control over all `ServiceChainResponse` content. This is a realistic network-level attack requiring no privileged access.

---

### Recommendation

1. **Validate response IDs**: Before writing to `rpcConn`, parse the JSON-RPC response and verify that the `id` field matches a currently pending outbound request ID tracked by the SubBridge.
2. **Authenticate bridge peers**: Require that bridge peers present a signature over the handshake data using a pre-configured public key (the known MainBridge node key), rejecting connections from unknown nodes.
3. **Whitelist peer node IDs**: Enforce that only the configured MainBridge node ID (from `SCConfig`) is accepted as a bridge peer, disconnecting any peer whose node ID does not match.

---

### Proof of Concept

1. Start a SubBridge node with a known `networkId` and `parentChainID`.
2. Connect a malicious node to the SubBridge's bridge P2P port; pass the handshake with the correct `networkId` and `chainID`.
3. Wait for the SubBridge to emit a `ServiceChainCall` P2P message (triggered by any `remoteBackend` call, e.g., during bridge contract interaction).
4. Extract the JSON-RPC `id` from the `ServiceChainCall` payload.
5. Send a `ServiceChainResponse` P2P message containing:
   ```json
   {"jsonrpc":"2.0","id":<extracted_id>,"result":"0xdeadbeef"}
   ```
6. Observe that `PendingNonceAt` returns `0xdeadbeef` (3,735,928,559) as the operator nonce.
7. The next bridge transaction is constructed with this forged nonce, is rejected by the parent chain, and the bridge stalls.

### Citations

**File:** node/sc/remote_backend.go (L47-54)
```go
func NewRpcClientP2P(sb *SubBridge) *rpc.Client {
	initctx := context.Background()
	c, _ := rpc.NewClient(initctx, func(ctx context.Context) (rpc.ServerCodec, error) {
		p1, p2 := net.Pipe()
		sb.SetRPCConn(p1)
		return rpc.NewCodec(p2), nil
	})
	return c
```

**File:** node/sc/remote_backend.go (L79-98)
```go
func (rb *RemoteBackend) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	if !rb.checkParentPeer() {
		return nil, NoParentPeerErr
	}
	var hex hexutil.Big
	err := rb.rpcClient.CallContext(ctx, &hex, "kaia_getBalance", account, toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

func (rb *RemoteBackend) CallContract(ctx context.Context, call kaia.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if !rb.checkParentPeer() {
		return nil, NoParentPeerErr
	}
	var hex hexutil.Bytes
	err := rb.rpcClient.CallContext(ctx, &hex, "kaia_call", toCallArg(call), toBlockNumArg(blockNumber))
	return hex, err
}
```

**File:** node/sc/remote_backend.go (L109-116)
```go
func (rb *RemoteBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	if !rb.checkParentPeer() {
		return 0, NoParentPeerErr
	}
	var result hexutil.Uint64
	err := rb.rpcClient.CallContext(ctx, &result, "kaia_getTransactionCount", account, "pending")
	return uint64(result), err
}
```

**File:** node/sc/subbridge.go (L240-261)
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
```

**File:** node/sc/subbridge.go (L511-531)
```go
func (sb *SubBridge) handle(p BridgePeer) error {
	// Ignore maxPeers if this is a trusted peer
	if sb.peers.Len() >= sb.maxPeers && !p.GetP2PPeer().Info().Networks[p2p.ConnDefault].Trusted {
		return p2p.DiscTooManyPeers
	}
	p.GetP2PPeer().Log().Debug("Kaia peer connected", "name", p.GetP2PPeer().Name())

	// Execute the handshake
	var (
		head   = sb.blockchain.CurrentHeader()
		hash   = head.Hash()
		number = head.Number.Uint64()
		td     = sb.blockchain.GetTd(hash, number)
	)

	err := p.Handshake(sb.networkId, sb.getChainID(), td, hash)
	if err != nil {
		p.GetP2PPeer().Log().Debug("Kaia peer handshake failed", "err", err)
		fmt.Println(err)
		return err
	}
```

**File:** node/sc/sub_bridge_handler.go (L233-246)
```go
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
```

**File:** node/sc/sub_bridge_handler.go (L463-473)
```go
func (sbh *SubBridgeHandler) RegisterNewPeer(p BridgePeer) error {
	sbh.subbridge.addPeerCh <- struct{}{}

	if sbh.getParentChainID().Cmp(p.GetChainID()) != 0 {
		return fmt.Errorf("attempt to add a peer with different chainID failed! existing chainID: %v, new chainID: %v", sbh.getParentChainID(), p.GetChainID())
	}
	// sync nonce and gasprice with peer
	sbh.SyncNonceAndGasPrice()

	return nil
}
```
