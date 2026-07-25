### Title
Unauthenticated Arbitrary RPC Dispatch via Bridge `ServiceChainCall` Message — (`node/sc/main_bridge_handler.go`)

---

### Summary

`MainBridgeHandler.handleCallMsg` forwards raw bytes received from any connected bridge P2P peer directly into the main bridge's internal `rpcServer` pipe with zero validation of the JSON-RPC method name or parameters. Because the internal RPC server has all public `kaia`/`klay` APIs registered — including `kaia_sendTransaction` which signs with unlocked node accounts — any peer that completes the trivial P2P handshake can invoke arbitrary RPC methods against the main chain node, bypassing all network-level access controls and potentially draining the bridge operator's unlocked account.

---

### Finding Description

**Setup — internal RPC server with full public API surface**

In `NewMainBridge`, an in-process `net.Pipe()` is created and one end is handed to a new `rpc.Server`:

```go
mb.rpcServer = rpc.NewServer()
p1, p2 := net.Pipe()
mb.rpcConn = p1
go mb.rpcServer.ServeCodec(rpc.NewCodec(p2), 0)
``` [1](#0-0) 

`SetComponents` then registers every public `kaia`/`klay` API — including `kaia_sendTransaction` — into this server:

```go
if api.Public && (api.Namespace == "klay" || api.Namespace == "kaia") {
    mb.rpcServer.RegisterName(api.Namespace, api.Service)
    ...
}
``` [2](#0-1) 

**The loose dispatch — no method whitelist**

When a bridge peer sends a `ServiceChainCall` (opcode `0x06`) P2P message, `handleCallMsg` decodes the raw bytes and writes them verbatim to `rpcConn`:

```go
func (mbh *MainBridgeHandler) handleCallMsg(p BridgePeer, msg p2p.Msg) error {
    data := make([]byte, msg.Size)
    err := msg.Decode(&data)
    ...
    // Write to RPC server pipe
    _, err = mbh.mainbridge.rpcConn.Write(data)
    ...
}
``` [3](#0-2) 

There is no check on:
- which JSON-RPC method is being called
- what parameters are supplied
- whether the calling peer is authorized to invoke that method

The response is read back from the pipe and forwarded to the peer via `SendRPCResponseData` → `SendResponseRPC` (opcode `0x07`). [4](#0-3) 

**Weak peer authentication**

The only gate before a peer can send `ServiceChainCall` messages is the P2P handshake, which checks only `NetworkId` and `ProtocolVersion`:

```go
if status.NetworkId != network {
    return errResp(ErrNetworkIdMismatch, ...)
}
if int(status.ProtocolVersion) != p.version {
    return errResp(ErrProtocolVersionMismatch, ...)
}
``` [5](#0-4) 

Both values are public constants (`SCProtocolName = "servicechain"`, `SCProtocolVersion = []uint{2}`). [6](#0-5) 

The bridge server is configured with `NoDiscovery = true` and `NoDial = true` but still **accepts** inbound connections on `MainBridgePort`. [7](#0-6) 

---

### Impact Explanation

**Tier 1 — network access-control bypass (certain)**

Operators commonly firewall the public JSON-RPC port (8551) while leaving the bridge P2P port (50505) open for legitimate service-chain connectivity. Any attacker who can reach port 50505 can now make arbitrary `kaia`/`klay` RPC calls that the firewall was intended to block.

**Tier 2 — unauthorized KAIA transfer from bridge operator account (high-probability)**

Bridge operators must keep their parent-chain operator account unlocked so the sub-bridge can sign and submit value-transfer transactions. `kaia_sendTransaction` is a public `kaia`-namespace API and is therefore registered in the internal `rpcServer`. A malicious bridge peer can craft the JSON-RPC payload:

```json
{
  "jsonrpc":"2.0","id":1,
  "method":"kaia_sendTransaction",
  "params":[{
    "from":"<bridge_operator_address>",
    "to":"<attacker_address>",
    "value":"0x<all_balance>"
  }]
}
```

and send it as a `ServiceChainCall` message. The internal RPC server signs the transaction with the unlocked account and submits it to the tx pool — transferring KAIA from the bridge operator's account to the attacker with no further authorization.

This satisfies the allowed-impact gate: **unauthorized transfer of KAIA from a system-managed (bridge operator) account**.

---

### Likelihood Explanation

- The bridge P2P port must be reachable from the service-chain side by design.
- The handshake requires only two public constants (NetworkId, ProtocolVersion).
- Bridge operator accounts are routinely kept unlocked in production deployments.
- The attacker needs no special cryptographic material — only network reachability to the bridge port.

---

### Recommendation

1. **Whitelist allowed RPC methods** in `handleCallMsg`. The only legitimate use of `ServiceChainCall` is querying nonce and gas price; restrict the allowed method set to an explicit allowlist (e.g., `kaia_getTransactionCount`, `kaia_gasPrice`).

2. **Do not register `kaia_sendTransaction` (or any account-signing method) in the bridge-internal RPC server.** The bridge-internal server should expose only read-only query methods.

3. **Authenticate bridge peers cryptographically** beyond the trivial NetworkId/ProtocolVersion check — e.g., require the peer's P2P public key to match a pre-configured allowlist of known service-chain operator keys.

---

### Proof of Concept

```go
// Attacker: any node that can reach the main bridge P2P port.
// 1. Connect to MainBridgePort, complete handshake with correct NetworkId + ProtocolVersion.
// 2. Craft a ServiceChainCall (0x06) message whose payload is a valid JSON-RPC request:

payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"kaia_sendTransaction","params":[{"from":"0x<bridge_operator>","to":"0x<attacker>","value":"0xDE0B6B3A7640000"}]}`)

// 3. RLP-encode and send as ServiceChainCall:
p2p.Send(rw, ServiceChainCall, payload)

// 4. The main bridge's handleCallMsg writes payload verbatim to rpcConn.
// 5. The internal rpcServer, which has kaia_sendTransaction registered and the
//    bridge operator account unlocked, signs and submits the transaction.
// 6. Read the ServiceChainResponse (0x07) to confirm the tx hash.
```

The exact corrupted value is the KAIA balance of the bridge operator's account, which is decremented by the attacker-specified `value` without any authorization from the account owner.

### Citations

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

**File:** node/sc/mainbridge.go (L303-306)
```go
	serverConfig.NoDiscovery = true
	serverConfig.EnableMultiChannelServer = false
	serverConfig.NoDial = true

```

**File:** node/sc/mainbridge.go (L401-413)
```go
func (mb *MainBridge) SendRPCResponseData(data []byte) error {
	peers := mb.BridgePeerSet().peers
	logger.Trace("mainbridge send rpc response data to peers", "data len", len(data), "peers", len(peers))
	for _, peer := range peers {
		err := peer.SendResponseRPC(data)
		if err != nil {
			logger.Error("failed to send rpc response to the peer", "err", err)
		}
		return err
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

**File:** node/sc/bridgepeer.go (L320-326)
```go
	if status.NetworkId != network {
		return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
	}
	if int(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}
	return nil
```

**File:** node/sc/protocol.go (L51-55)
```go
var (
	SCProtocolName    = "servicechain"
	SCProtocolVersion = []uint{2}
	SCProtocolLength  = []uint64{10}
)
```
