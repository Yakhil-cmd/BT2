### Title
Unfiltered Raw P2P-to-RPC Passthrough in `handleCallMsg` Enables Arbitrary Parent-Chain RPC Execution via Bridge Peer — (File: `node/sc/main_bridge_handler.go`)

---

### Summary

The `MainBridgeHandler.handleCallMsg` function accepts raw bytes from any connected bridge peer via a `ServiceChainCall` P2P message and writes them directly into the parent chain's internal RPC server pipe without any method filtering, validation, or access control. Because the MainBridge registers all public `kaia`/`klay` APIs — including `kaia_sendTransaction` — on that internal server, any node that can complete the bridge P2P handshake can invoke arbitrary RPC methods against the parent chain, including signing and submitting transactions from the unlocked bridge operator account.

---

### Finding Description

**Step 1 — RPC server setup with full public API surface**

In `NewMainBridge`, an internal `rpc.Server` is created and connected to a `net.Pipe`. All public `kaia`/`klay` APIs from the parent chain node are registered on it:

```go
// mainbridge.go:153-156
mb.rpcServer = rpc.NewServer()
p1, p2 := net.Pipe()
mb.rpcConn = p1
go mb.rpcServer.ServeCodec(rpc.NewCodec(p2), 0)
```

```go
// mainbridge.go:243-254
if api.Public && (api.Namespace == "klay" || api.Namespace == "kaia") {
    mb.rpcServer.RegisterName("klay", api.Service)
    mb.rpcServer.RegisterName("kaia", api.Service)
}
```

This includes `KaiaTransactionAPI` (registered as `Public: true` in `node/cn/backend.go:710-714`), which exposes `kaia_sendTransaction`, `kaia_sendTransactionAsFeePayer`, and `kaia_sendRawTransaction`.

**Step 2 — Raw passthrough with no filtering**

When a `ServiceChainCall` P2P message arrives from any bridge peer, `handleCallMsg` reads the raw bytes and writes them directly to the RPC server pipe:

```go
// main_bridge_handler.go:86-101
func (mbh *MainBridgeHandler) handleCallMsg(p BridgePeer, msg p2p.Msg) error {
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    // Write to RPC server pipe
    _, err = mbh.mainbridge.rpcConn.Write(data)
    return nil
}
```

There is no allowlist of permitted methods, no body validation, and no per-call authentication.

**Step 3 — Bridge handshake provides no meaningful authentication**

The bridge peer handshake (`bridgepeer.go:267-327`) only checks `NetworkId` and `ProtocolVersion`. Any node that knows the bridge P2P address and can match those two values is accepted as a bridge peer. There is no shared secret, certificate, or application-level credential.

**Step 4 — `kaia_sendTransaction` signs with unlocked keystore accounts**

`KaiaTransactionAPI.SendTransaction` calls `s.sign(args.From, tx)`, which signs using any account currently unlocked in the node's keystore. In a standard MainBridge deployment the bridge operator account is kept unlocked to sign bridge relay transactions automatically.

---

### Impact Explanation

An attacker who connects to the MainBridge P2P port and completes the bridge handshake can craft a `ServiceChainCall` message containing:

```json
{"jsonrpc":"2.0","method":"kaia_sendTransaction",
 "params":[{"from":"<bridge_operator_addr>","to":"<attacker_addr>","value":"<balance>"}],
 "id":1}
```

The MainBridge writes this payload to its internal RPC server, which executes `kaia_sendTransaction`, signs the transaction with the unlocked bridge operator key, and submits it to the parent chain tx pool. This results in an **unauthorized KAIA transfer from the bridge operator account** — a system-managed fund — to an attacker-controlled address.

The same path allows calling `kaia_sendTransactionAsFeePayer` to consume the operator's KAIA as fee payer for attacker-crafted transactions, or `kaia_sendRawTransaction` to inject arbitrary pre-signed transactions into the parent chain tx pool.

---

### Likelihood Explanation

**Medium.** The bridge P2P port is a separate listener (configured via `--bridge.port`) that must be reachable by child chain nodes. In any production service-chain deployment this port is network-accessible. The handshake requires only matching `NetworkId` and `ProtocolVersion`, both of which are public chain parameters. The bridge operator account being unlocked is the normal operating condition for a functioning MainBridge. No privileged keys or majority-validator collusion are required.

---

### Recommendation

1. **Allowlist permitted RPC methods** inside `handleCallMsg`. Inspect the decoded JSON-RPC `method` field before writing to the pipe and reject anything not in the set of methods `RemoteBackend` legitimately calls (`kaia_getCode`, `kaia_getBalance`, `kaia_call`, `kaia_getTransactionCount`, `kaia_gasPrice`, `kaia_estimateGas`, `kaia_getTransactionReceipt`, `kaia_getLogs`, `kaia_blockNumber`).

2. **Register a restricted API set** on `mb.rpcServer` instead of all public `kaia` APIs. Create a dedicated read-only interface for bridge use rather than reusing the full `KaiaTransactionAPI`.

3. **Authenticate bridge peers** beyond network/version matching — e.g., require the peer's node ID to appear in a configured allowlist before accepting `ServiceChainCall` messages.

---

### Proof of Concept

```
# 1. Attacker node connects to MainBridge P2P port (e.g., :50505)
#    Completes bridge handshake with matching NetworkId + ProtocolVersion.

# 2. Attacker sends a ServiceChainCall P2P message whose payload is:
payload = RLP_encode(
    JSON: {"jsonrpc":"2.0","method":"kaia_sendTransaction",
           "params":[{"from":"0xBRIDGE_OPERATOR","to":"0xATTACKER",
                      "value":"0x<full_balance_hex>","gas":"0x5208"}],
           "id":1}
)
send_p2p_msg(code=ServiceChainCall, data=payload)

# 3. MainBridgeHandler.handleCallMsg writes payload to mb.rpcConn (mainbridge.go:96).
# 4. mb.rpcServer executes kaia_sendTransaction → signs with unlocked operator key.
# 5. Signed tx enters parent chain tx pool → mined → KAIA transferred to attacker.
# 6. RPC response is returned to attacker via SendRPCResponseData.
```

**Affected files and lines:**

- [1](#0-0)  — `handleCallMsg`: raw bytes written to RPC pipe with no method filtering.
- [2](#0-1)  — internal RPC server and pipe creation.
- [3](#0-2)  — all public `kaia`/`klay` APIs registered on the internal server.
- [4](#0-3)  — bridge handshake: only `NetworkId` and `ProtocolVersion` checked, no peer authentication.
- [5](#0-4)  — `KaiaTransactionAPI` registered as `Public: true` in the `kaia` namespace, making `kaia_sendTransaction` available on the bridge's internal RPC server.
- [6](#0-5)  — `kaia_sendTransaction` signs with the unlocked keystore account and submits to the tx pool.

### Citations

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

**File:** node/sc/mainbridge.go (L153-156)
```go
	mb.rpcServer = rpc.NewServer()
	p1, p2 := net.Pipe()
	mb.rpcConn = p1
	go mb.rpcServer.ServeCodec(rpc.NewCodec(p2), 0)
```

**File:** node/sc/mainbridge.go (L239-255)
```go
		case []rpc.API:
			logger.Debug("p2p rpc registered", "len(v)", len(v))
			for _, api := range v {
				// TODO-Kaia-RPC: cleanup
				if api.Public && (api.Namespace == "klay" || api.Namespace == "kaia") {
					api.Namespace = "klay"
					logger.Error("p2p rpc registered", "namespace", api.Namespace)
					if err := mb.rpcServer.RegisterName(api.Namespace, api.Service); err != nil {
						logger.Error("pRPC failed to register", "namespace", api.Namespace)
					}
					api.Namespace = "kaia"
					logger.Error("p2p rpc registered", "namespace", api.Namespace)
					if err := mb.rpcServer.RegisterName(api.Namespace, api.Service); err != nil {
						logger.Error("pRPC failed to register", "namespace", api.Namespace)
					}
				}
			}
```

**File:** node/sc/bridgepeer.go (L305-327)
```go
func (p *baseBridgePeer) readStatus(network uint64, status *statusData) error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, ProtocolMaxMsgSize)
	}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	if status.NetworkId != network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if int(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
}
```

**File:** node/cn/backend.go (L710-714)
```go
		}, {
			Namespace: "kaia",
			Version:   "1.0",
			Service:   kaiaTransactionAPI,
			Public:    true,
```

**File:** api/api_kaia_transaction.go (L337-350)
```go
func (s *KaiaTransactionAPI) SendTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {
	if args.AccountNonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	signedTx, err := s.SignTransaction(ctx, args)
	if err != nil {
		return common.Hash{}, err
	}

	return submitTransaction(ctx, s.b, signedTx.Tx)
```
