### Title
Unauthenticated Admin HTTP API Exposes Privileged Node State Mutation to Any Network-Reachable Caller - (File: `admin/command_runner.go`)

### Summary
The Flow node admin HTTP server (`CommandRunner`) exposes all registered privileged commands — including consensus parameter mutation, node halting, and rate-limit bypass — over a plain HTTP endpoint with no mandatory authentication. TLS/mTLS is optional and off by default. Any entity that can reach the admin port can invoke every registered command with no identity verification. The ledger service admin server (`cmd/ledger/admin.go`) has no TLS option at all.

### Finding Description
`CommandRunner.runAdminServer()` starts two servers: a Unix-socket gRPC backend and an HTTP frontend bound to the operator-supplied `httpAddress`. The HTTP server is started with `httpServer.ListenAndServe()` when `r.tlsConfig == nil`, which is the default state. [1](#0-0) 

TLS is only applied when the operator explicitly passes all three of `--admin-cert`, `--admin-key`, and `--admin-client-cas`. The scaffold wires this up as an optional branch: [2](#0-1) 

The `runCommand()` dispatcher performs no caller identity check. It only validates the command's data payload: [3](#0-2) 

The ledger service admin handler (`cmd/ledger/admin.go`) has no TLS path at all — it is always plain HTTP with no authentication: [4](#0-3) [5](#0-4) 

The documentation and README explicitly show `0.0.0.0:9003` as the example bind address for the ledger service admin server, and `0.0.0.0:9002` is the conventional port for node admin servers: [6](#0-5) 

The registered default admin commands include highly privileged operations: [7](#0-6) 

Specifically, `set-config` allows mutating `consensus-required-approvals-for-sealing`, `stop-at-height` halts execution/verification nodes, and `ingest-tx-rate-limit` manipulates collection node mempool rate limiting. [8](#0-7) 

### Impact Explanation
An attacker who can reach the admin HTTP port can:

1. **Consensus safety bypass**: Send `set-config` with `{"consensus-required-approvals-for-sealing": 0}` to a consensus node, disabling the approval threshold required before blocks are sealed. This is a direct integrity failure in the consensus/sealing pipeline.
2. **Node halting**: Send `stop-at-height` to execution or verification nodes, halting block processing at an attacker-chosen height.
3. **Rate-limit bypass on collection nodes**: Send `ingest-tx-rate-limit` with `command: "remove"` to remove rate-limit entries, or `set_config` to set limits to zero, bypassing mempool spam protection.

These are unauthorized state mutations of staked protocol nodes with direct protocol-level impact.

### Likelihood Explanation
The admin server bind address is operator-configured with no code-level enforcement of localhost-only binding. The official documentation and README explicitly show `0.0.0.0:9002`/`0.0.0.0:9003` as example addresses. In containerized or cloud deployments where the admin port is exposed on a non-loopback interface (e.g., for monitoring or orchestration tooling), any network-reachable entity — including an unprivileged Access/Observer node peer or external API caller — can reach the endpoint. TLS/mTLS is opt-in and absent by default, meaning the majority of deployments that do not explicitly configure all three TLS flags run with a fully open admin API.

### Recommendation
1. Enforce localhost-only binding by default for the admin HTTP server; require explicit opt-in to bind on non-loopback interfaces.
2. Make mTLS mandatory rather than optional; reject startup if `--admin-addr` is set without corresponding TLS credentials.
3. Add a caller-identity check inside `runCommand()` (e.g., verify the connecting client certificate or a shared secret token) so that even if the port is reachable, unauthenticated callers are rejected.
4. For the ledger service admin handler (`cmd/ledger/admin.go`), add TLS support with the same mTLS enforcement.

### Proof of Concept
```bash
# Against a node with admin server bound to 0.0.0.0:9002 (no TLS configured):

# 1. Disable consensus sealing approval requirement on a consensus node
curl -s http://<NODE_IP>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'

# 2. Halt an execution node at the next block
curl -s http://<NODE_IP>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "stop-at-height", "data": {"height": 1, "crash": false}}'

# 3. Against ledger service (no TLS option exists):
curl -s http://<LEDGER_IP>:9003/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "trigger-checkpoint"}'
```

No credentials, keys, or privileged access are required. The only precondition is network reachability to the admin port.

### Citations

**File:** admin/command_runner.go (L249-265)
```go
	httpServer := &http.Server{
		Addr:      r.httpAddress,
		Handler:   mux,
		TLSConfig: r.tlsConfig,
	}

	r.workersStarted.Add(1)
	r.workersFinished.Go(func() {
		r.workersStarted.Done()

		// Start HTTP server (and proxy calls to gRPC server endpoint)
		var err error
		if r.tlsConfig == nil {
			err = httpServer.ListenAndServe()
		} else {
			err = httpServer.ListenAndServeTLS("", "")
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

**File:** cmd/scaffold.go (L2024-2045)
```go
func (fnb *FlowNodeBuilder) RegisterDefaultAdminCommands() {
	fnb.AdminCommand("set-log-level", func(config *NodeConfig) commands.AdminCommand {
		return &common.SetLogLevelCommand{}
	}).AdminCommand("set-golog-level", func(config *NodeConfig) commands.AdminCommand {
		return &common.SetGologLevelCommand{}
	}).AdminCommand("get-config", func(config *NodeConfig) commands.AdminCommand {
		return common.NewGetConfigCommand(config.ConfigManager)
	}).AdminCommand("set-config", func(config *NodeConfig) commands.AdminCommand {
		return common.NewSetConfigCommand(config.ConfigManager)
	}).AdminCommand("list-configs", func(config *NodeConfig) commands.AdminCommand {
		return common.NewListConfigCommand(config.ConfigManager)
	}).AdminCommand("read-blocks", func(config *NodeConfig) commands.AdminCommand {
		return storageCommands.NewReadBlocksCommand(config.State, config.Storage.Blocks)
	}).AdminCommand("read-range-blocks", func(conf *NodeConfig) commands.AdminCommand {
		return storageCommands.NewReadRangeBlocksCommand(conf.Storage.Blocks)
	}).AdminCommand("read-results", func(config *NodeConfig) commands.AdminCommand {
		return storageCommands.NewReadResultsCommand(config.State, config.Storage.Results)
	}).AdminCommand("read-seals", func(config *NodeConfig) commands.AdminCommand {
		return storageCommands.NewReadSealsCommand(config.State, config.Storage.Seals, config.Storage.Index)
	}).AdminCommand("get-latest-identity", func(config *NodeConfig) commands.AdminCommand {
		return common.NewGetIdentityCommand(config.IdentityProvider)
	})
```

**File:** cmd/ledger/admin.go (L36-46)
```go
func newAdminHandler(logger zerolog.Logger, triggerCheckpoint *atomic.Bool) http.Handler {
	h := &adminHandler{
		logger:            logger.With().Str("component", "admin").Logger(),
		triggerCheckpoint: triggerCheckpoint,
		commands:          []string{"ping", "list-commands", "trigger-checkpoint"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/run_command", h.handleCommand)
	return mux
}
```

**File:** cmd/ledger/main.go (L231-243)
```go
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
```

**File:** cmd/ledger/README.md (L42-46)
```markdown
# With admin server enabled (use port 9003 to avoid conflict with execution node's 9002)
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000 \
  -admin-addr 0.0.0.0:9003
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
