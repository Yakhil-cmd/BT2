### Title
Unauthenticated `Set()` RPC on Ledger gRPC Service Allows Arbitrary Execution-State Mutation — (`cmd/ledger/main.go`, `ledger/remote/service.go`)

### Summary

The standalone ledger service (`cmd/ledger`) exposes a gRPC `LedgerService/Set` RPC that writes arbitrary key-value pairs directly into the execution-state ledger. The gRPC server is created with no authentication interceptors and can be bound to `0.0.0.0:9000` (all interfaces). Any network-reachable caller — with no credentials — can invoke `Set()` and overwrite any register in the execution state, corrupting Flow's on-chain state.

A secondary, lower-impact instance exists in the same binary: the admin HTTP server (`cmd/ledger/admin.go`) also has no authentication and can be bound to `0.0.0.0:9003`, allowing unauthenticated `trigger-checkpoint` commands.

### Finding Description

**Root cause — gRPC server (primary):**

`cmd/ledger/main.go` creates the gRPC server with no `grpc.UnaryInterceptor` or `grpc.StreamInterceptor` for authentication:

```go
grpcServer := grpc.NewServer(
    grpc.MaxRecvMsgSize(int(*maxRequestSize)),
    grpc.MaxSendMsgSize(int(*maxResponseSize)),
)
``` [1](#0-0) 

It then registers the `LedgerService` server and binds to TCP:

```go
ledgerpb.RegisterLedgerServiceServer(grpcServer, ledgerService)
// ...
lis, err := net.Listen("tcp", *ledgerServiceTCP)
``` [2](#0-1) 

The `--ledger-service-tcp` flag is documented with the example `0.0.0.0:9000`: [3](#0-2) 

`ledger/remote/service.go`'s `Set()` handler performs only basic structural validation (non-nil state, non-empty keys, matching lengths) and then directly calls `s.ledger.Set(update)` — no caller identity check, no token, no TLS requirement:

```go
func (s *Service) Set(ctx context.Context, req *ledgerpb.SetRequest) (*ledgerpb.SetResponse, error) {
    if req.State == nil || len(req.State.Hash) != len(ledger.State{}) {
        return nil, status.Error(codes.InvalidArgument, "invalid state")
    }
    // ... structural checks only ...
    newState, trieUpdate, err := s.ledger.Set(update)
``` [4](#0-3) 

The gRPC proto definition confirms `Set` is a state-mutating RPC exposed without any security annotation: [5](#0-4) 

**Root cause — admin HTTP server (secondary):**

`cmd/ledger/admin.go`'s `handleCommand` checks only the HTTP method (`POST`) and JSON validity; there is no token, IP allowlist, or TLS check before executing commands:

```go
func (h *adminHandler) handleCommand(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost { ... }
    // no authentication check
    switch req.CommandName {
    case "trigger-checkpoint":
        h.triggerCheckpoint.CompareAndSwap(false, true)
``` [6](#0-5) 

The server is started with plain `ListenAndServe` (no TLS): [7](#0-6) 

Note: the main Flow-node admin server (`admin/command_runner.go`) supports optional mutual-TLS via `WithTLS` and is documented as requiring it for production. The ledger service admin server has no such option at all. [8](#0-7) 

### Impact Explanation

**Primary (gRPC `Set`):** An attacker who can reach TCP port 9000 on the ledger service host can call `LedgerService/Set` with an arbitrary state root and arbitrary key-value pairs. This directly overwrites registers in the execution-state trie. Consequences include:

- Corrupting account balances, contract code, or capability storage for any Flow account.
- Causing execution nodes to produce incorrect execution results, breaking consensus on sealed blocks.
- Enabling theft of on-chain assets by overwriting token balances or capability links.

**Secondary (admin HTTP `trigger-checkpoint`):** An attacker can force premature WAL checkpoints, potentially disrupting ledger compaction timing. Impact is operational disruption rather than direct asset theft.

### Likelihood Explanation

The README explicitly documents binding to `0.0.0.0:9000` and `0.0.0.0:9003` as the intended deployment pattern. Any host or container that can reach those ports — including other services in the same cluster, or the public internet if firewall rules are absent — can exploit this with a single gRPC call. No credentials, no prior knowledge beyond the port number, and no special tooling beyond `grpcurl` are required.

### Recommendation

1. Add a gRPC `UnaryInterceptor` (and `StreamInterceptor`) to the ledger gRPC server that enforces mutual TLS or a shared-secret token before allowing any RPC, especially `Set`.
2. Restrict the ledger service TCP listener to `127.0.0.1` or a Unix socket by default; require explicit opt-in for network binding.
3. Add the same `WithTLS` / mutual-TLS option to the ledger admin HTTP server that the main Flow-node admin server already supports.
4. Document that the ledger service must never be exposed to untrusted networks without authentication.

### Proof of Concept

```bash
# Attacker with network access to the ledger service TCP port
# Obtain the current initial state (unauthenticated read):
grpcurl -plaintext \
  -d '{}' \
  <ledger-host>:9000 \
  ledger.LedgerService/InitialState

# Overwrite an arbitrary register (e.g., a token balance register):
grpcurl -plaintext \
  -d '{
    "state": {"hash": "<base64-of-current-state-hash>"},
    "keys": [{"parts": [
      {"type": 0, "value": "<base64-of-target-account-address>"},
      {"type": 2, "value": "<base64-of-register-key>"}
    ]}],
    "values": [{"data": "<base64-of-attacker-chosen-value>", "is_nil": false}]
  }' \
  <ledger-host>:9000 \
  ledger.LedgerService/Set
# Returns a new state root reflecting the corrupted register.
# The execution node will use this corrupted state for subsequent block execution.
```

### Citations

**File:** cmd/ledger/main.go (L121-124)
```go
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(int(*maxRequestSize)),
		grpc.MaxSendMsgSize(int(*maxResponseSize)),
	)
```

**File:** cmd/ledger/main.go (L128-153)
```go
	ledgerpb.RegisterLedgerServiceServer(grpcServer, ledgerService)

	// Create listeners based on provided flags
	type listenerInfo struct {
		listener     net.Listener
		address      string
		socketPath   string
		isUnixSocket bool
	}
	var listeners []listenerInfo
	var socketPaths []string

	// Create TCP listener if TCP address is provided
	if *ledgerServiceTCP != "" {
		lis, err := net.Listen("tcp", *ledgerServiceTCP)
		if err != nil {
			logger.Fatal().Err(err).Str("address", *ledgerServiceTCP).Msg("failed to listen on TCP")
		}

		logger.Info().Str("address", *ledgerServiceTCP).Msg("gRPC server listening on TCP")
		listeners = append(listeners, listenerInfo{
			listener:     lis,
			address:      *ledgerServiceTCP,
			socketPath:   "",
			isUnixSocket: false,
		})
```

**File:** cmd/ledger/main.go (L230-244)
```go
	var adminServer *http.Server
	if *adminAddr != "" {
		adminHandler := newAdminHandler(logger, triggerCheckpointOnNextSegmentFinish)
		adminServer = &http.Server{
			Addr:    *adminAddr,
			Handler: adminHandler,
		}

		go func() {
			logger.Info().Str("admin_addr", *adminAddr).Msg("starting admin HTTP server")
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error().Err(err).Msg("admin HTTP server error")
			}
		}()
	}
```

**File:** cmd/ledger/README.md (L24-46)
```markdown
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000

# Listen on Unix socket only
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-socket /sockets/ledger.sock

# Listen on both TCP and Unix socket
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000 \
  -ledger-service-socket /sockets/ledger.sock \
  -mtrie-cache-size 500 \
  -checkpoint-distance 100 \
  -checkpoints-to-keep 3

# With admin server enabled (use port 9003 to avoid conflict with execution node's 9002)
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000 \
  -admin-addr 0.0.0.0:9003
```

**File:** ledger/remote/service.go (L133-186)
```go
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
```

**File:** ledger/protobuf/ledger.proto (L23-24)
```text
  // Set updates keys with new values at a specific state and returns the new state
  rpc Set(SetRequest) returns (SetResponse);
```

**File:** cmd/ledger/admin.go (L48-87)
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

	var result any

	switch req.CommandName {
	case "ping":
		result = "pong"

	case "list-commands":
		result = h.commands

	case "trigger-checkpoint":
		if h.triggerCheckpoint.CompareAndSwap(false, true) {
			h.logger.Info().Msg("trigger checkpoint as soon as finishing writing the current segment file")
			result = "ok"
		} else {
			result = "checkpoint already triggered"
		}

	default:
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown command: %s", req.CommandName))
		return
	}

	h.writeSuccess(w, result)
}
```

**File:** cmd/scaffold.go (L756-775)
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
		}
```
