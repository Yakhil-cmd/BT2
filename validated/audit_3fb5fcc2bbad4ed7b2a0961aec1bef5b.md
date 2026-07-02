### Title
Unauthenticated `Set()` RPC on the Remote Ledger Service Allows Any Network-Reachable Caller to Corrupt Execution State - (`cmd/ledger/main.go`, `ledger/remote/service.go`)

---

### Summary

The standalone `flow-ledger-service` binary exposes a gRPC `LedgerService` over a plain TCP socket (`--ledger-service-tcp 0.0.0.0:9000`) with **no transport-layer security and no caller authentication**. The `Set()` RPC mutates the execution-state MTrie directly. Any process that can reach the TCP port — including any unprivileged process on the same host or any host on the same network segment — can call `Set()` and write arbitrary key/value pairs into the ledger, producing a forked or corrupted execution state root that the attached Execution Node will use for subsequent block execution.

---

### Finding Description

**Root cause — no authentication on the gRPC server**

`cmd/ledger/main.go` creates the gRPC server with only message-size options and no transport credentials or interceptor:

```go
grpcServer := grpc.NewServer(
    grpc.MaxRecvMsgSize(int(*maxRequestSize)),
    grpc.MaxSendMsgSize(int(*maxResponseSize)),
)
``` [1](#0-0) 

The server is then bound to a plain TCP listener when `--ledger-service-tcp` is supplied:

```go
lis, err := net.Listen("tcp", *ledgerServiceTCP)
``` [2](#0-1) 

The `LedgerService` proto exposes a `Set` RPC that writes arbitrary key/value pairs into the live MTrie:

```proto
rpc Set(SetRequest) returns (SetResponse);
``` [3](#0-2) 

The server-side handler `Service.Set()` performs only structural validation (non-nil state hash, non-empty keys, matching lengths) and then calls `s.ledger.Set(update)` unconditionally — there is no caller identity check, no token, no TLS mutual-auth, nothing:

```go
func (s *Service) Set(ctx context.Context, req *ledgerpb.SetRequest) (*ledgerpb.SetResponse, error) {
    // ... structural checks only ...
    newState, trieUpdate, err := s.ledger.Set(update)
``` [4](#0-3) 

The remote client used by the Execution Node also connects with `insecure.NewCredentials()`, confirming the channel is plaintext end-to-end:

```go
conn, err = grpc.NewClient(
    grpcAddr,
    grpc.WithTransportCredentials(insecure.NewCredentials()),
``` [5](#0-4) 

**Contrast with the node admin server**, which at least supports optional mutual-TLS (`AdminCert`/`AdminKey`/`AdminClientCAs`) and binds to a Unix socket by default:

```go
if node.AdminCert != NotSet {
    // ... load TLS certs, require client cert ...
    opts = append(opts, admin.WithTLS(config))
}
``` [6](#0-5) 

The ledger service has no equivalent protection path at all.

**Attack path**

1. Operator deploys `flow-ledger-service` with `--ledger-service-tcp 0.0.0.0:9000` (the documented TCP mode).
2. Attacker on the same network (or same host) connects to port 9000 with any standard gRPC client.
3. Attacker calls `InitialState()` (unauthenticated read) to obtain the current root state hash.
4. Attacker calls `Set(state, keys, values)` with the current root hash and crafted key/value pairs — e.g., overwriting an account's balance register or a contract's bytecode register.
5. The ledger returns a new state root reflecting the attacker's writes.
6. The Execution Node, which delegates all ledger operations to this service, uses the corrupted state root for the next block it executes, producing an invalid execution receipt.
7. Verification Nodes will reject the receipt; the Execution Node is effectively slashed or stalled.

---

### Impact Explanation

- **Execution state corruption**: arbitrary register values can be written, including account balances, contract code, and capability storage. This is equivalent to unauthorized mutation of every Flow account on the chain served by this Execution Node.
- **Consensus integrity failure**: the corrupted execution receipt will not match honest Verification Nodes, causing the Execution Node's receipts to be rejected and potentially triggering slashing or a halt of that node's contribution to the network.
- **No cryptographic barrier**: the attack requires only TCP connectivity to the ledger service port — no keys, no staked identity, no Flow account.

---

### Likelihood Explanation

The `--ledger-service-tcp` flag is the primary documented deployment mode in `cmd/ledger/README.md`:

```
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000
``` [7](#0-6) 

Any misconfiguration that exposes port 9000 beyond localhost (e.g., a cloud firewall rule, a shared-tenant host, or a container network without isolation) immediately makes the `Set()` RPC reachable by an unprivileged attacker. The README does not warn operators to firewall this port or use Unix sockets exclusively.

---

### Recommendation

1. **Require mutual TLS on the TCP listener**: generate a server certificate at startup and require clients to present a certificate signed by a trusted CA, mirroring the pattern used by the node admin server (`cmd/scaffold.go` lines 756–774).
2. **Add a gRPC server interceptor** that rejects any call that did not arrive over an authenticated TLS connection.
3. **Document that the TCP listener must be firewalled** to the Execution Node's IP only, or prefer the Unix socket transport (`--ledger-service-socket`) which is protected by OS filesystem permissions.
4. **Restrict `Set()` at the service layer**: add a caller-identity check so that only the co-located Execution Node process (identified by its TLS certificate or Unix peer credential) may invoke write operations.

---

### Proof of Concept

```bash
# 1. Start the ledger service in TCP mode (as documented)
./flow-ledger-service -triedir /path/to/trie -ledger-service-tcp 0.0.0.0:9000

# 2. From any host that can reach port 9000, use grpcurl (no credentials needed):

# Get the current root state
grpcurl -plaintext -d '{}' <EN_HOST>:9000 ledger.LedgerService/InitialState
# Returns: {"state":{"hash":"<BASE64_ROOT_HASH>"}}

# 3. Overwrite an arbitrary register (e.g., account balance key)
grpcurl -plaintext -d '{
  "state": {"hash": "<BASE64_ROOT_HASH>"},
  "keys": [{"parts": [{"type": 0, "value": "<ACCOUNT_ADDR>"}, {"type": 2, "value": "Zmxvd1Rva2VuQmFsYW5jZQ=="}]}],
  "values": [{"data": "AAAAAAAAAAA=", "is_nil": false}]
}' <EN_HOST>:9000 ledger.LedgerService/Set
# Returns a new state hash — the ledger is now corrupted.
# The Execution Node will use this corrupted state for the next block.
```

The `Set()` call succeeds with no authentication because `grpc.NewServer()` in `cmd/ledger/main.go` carries no `grpc.Creds(...)` option and `Service.Set()` in `ledger/remote/service.go` performs no caller verification. [8](#0-7) [9](#0-8)

### Citations

**File:** cmd/ledger/main.go (L121-128)
```go
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(int(*maxRequestSize)),
		grpc.MaxSendMsgSize(int(*maxResponseSize)),
	)

	// Create and register ledger service
	ledgerService := remote.NewService(ledgerStorage, logger)
	ledgerpb.RegisterLedgerServiceServer(grpcServer, ledgerService)
```

**File:** cmd/ledger/main.go (L142-143)
```go
		lis, err := net.Listen("tcp", *ledgerServiceTCP)
		if err != nil {
```

**File:** ledger/protobuf/ledger.proto (L23-24)
```text
  // Set updates keys with new values at a specific state and returns the new state
  rpc Set(SetRequest) returns (SetResponse);
```

**File:** ledger/remote/service.go (L132-183)
```go
// Set updates keys with new values at a specific state and returns the new state
func (s *Service) Set(ctx context.Context, req *ledgerpb.SetRequest) (*ledgerpb.SetResponse, error) {
	if req.State == nil || len(req.State.Hash) != len(ledger.State{}) {
		return nil, status.Error(codes.InvalidArgument, "invalid state")
	}

	if len(req.Keys) == 0 {
		return nil, status.Error(codes.InvalidArgument, "keys cannot be empty")
	}

	if len(req.Keys) != len(req.Values) {
		return nil, status.Error(codes.InvalidArgument, "keys and values length mismatch")
	}

	var state ledger.State
	copy(state[:], req.State.Hash)

	keys := make([]ledger.Key, len(req.Keys))
	for i, protoKey := range req.Keys {
		key, err := protoKeyToLedgerKey(protoKey)
		if err != nil {
			return nil, err // protoKeyToLedgerKey already returns status.Error
		}
		keys[i] = key
	}

	values := make([]ledger.Value, len(req.Values))
	for i, protoValue := range req.Values {
		var value ledger.Value
		// Reconstruct the original value type using is_nil flag
		// This preserves the distinction between nil and []byte{} that protobuf loses
		if len(protoValue.Data) == 0 {
			if protoValue.IsNil {
				// Original value was nil
				value = nil
			} else {
				// Original value was []byte{} (empty slice)
				value = ledger.Value([]byte{})
			}
		} else {
			// Non-empty value, use data as-is
			value = ledger.Value(protoValue.Data)
		}
		values[i] = value
	}

	update, err := ledger.NewUpdate(state, keys, values)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	newState, trieUpdate, err := s.ledger.Set(update)
```

**File:** ledger/remote/client.go (L108-111)
```go
		conn, err = grpc.NewClient(
			grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(
```

**File:** cmd/scaffold.go (L756-774)
```go
		if node.AdminCert != NotSet {
			serverCert, err := tls.LoadX509KeyPair(node.AdminCert, node.AdminKey)
			if err != nil {
				return nil, err
			}
			clientCAs, err := os.ReadFile(node.AdminClientCAs)
			if err != nil {
				return nil, err
			}
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(clientCAs)
			config := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    certPool,
			}

			opts = append(opts, admin.WithTLS(config))
```

**File:** cmd/ledger/README.md (L23-27)
```markdown
# Listen on TCP only
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000

```
