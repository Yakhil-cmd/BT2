### Title
Unauthenticated Admin HTTP Server Allows Any Network-Reachable Caller to Modify Critical Consensus Parameters - (`admin/command_runner.go`)

### Summary
The Flow node admin server exposes an HTTP endpoint that allows dynamic modification of critical protocol parameters (e.g., `consensus-required-approvals-for-sealing`, `cruise-ctl-*`, `network-id-provider-blocklist`, `stop-at-height`). When TLS mutual authentication is not configured — which is the default — the HTTP server performs **zero caller identity verification**. Any entity that can reach the admin HTTP port can invoke any registered admin command, including those that alter consensus safety parameters, without any authorization check. This is the direct analog of the VeloGovernor finding: a privileged operation (changing critical protocol parameters) is gated only by network reachability rather than a proper governance/authorization mechanism.

### Finding Description

`admin/command_runner.go` starts two servers in `runAdminServer`:

1. A gRPC server bound to a **Unix domain socket** (local-only, not directly reachable from the network).
2. An HTTP/gRPC-gateway server bound to `r.httpAddress` — a configurable TCP address — that proxies all requests to the Unix socket gRPC server.

The gRPC server is created with no authentication interceptors:

```go
opts := []grpc.ServerOption{
    grpc.MaxRecvMsgSize(r.maxMsgSize),
    grpc.MaxSendMsgSize(r.maxMsgSize),
}
grpcServer := grpc.NewServer(opts...)
```

The HTTP server starts without TLS when `r.tlsConfig == nil`:

```go
if r.tlsConfig == nil {
    err = httpServer.ListenAndServe()
} else {
    err = httpServer.ListenAndServeTLS("", "")
}
```

TLS with mutual client certificate authentication is only enabled if the operator explicitly provides `--admin-cert`, `--admin-key`, and `--admin-client-cas` flags. This is checked in `cmd/scaffold.go`:

```go
if node.AdminCert != NotSet {
    // ... load TLS config
    opts = append(opts, admin.WithTLS(config))
}
```

When TLS is absent (the default), the `runCommand` function dispatches any command from any caller with no identity check:

```go
func (r *CommandRunner) runCommand(ctx context.Context, command string, data any) (any, error) {
    req := &CommandRequest{Data: data}
    if validator := r.getValidator(command); validator != nil {
        // only validates input format, not caller identity
        ...
    }
    if handler := r.getHandler(command); handler != nil {
        handleResult, handleErr = handler(ctx, req)
    }
    ...
}
```

The `set-config` command (`admin/commands/common/set_config.go`) applies any registered updatable config field without any caller check:

```go
func (s *SetConfigCommand) Handler(_ context.Context, req *admin.CommandRequest) (any, error) {
    validatedReq := req.ValidatorData.(validatedSetConfigData)
    err := validatedReq.field.Set(validatedReq.value)
    ...
}
```

Registered updatable fields on a consensus node include `consensus-required-approvals-for-sealing` (which controls how many verification approvals are required before a seal is constructed), `cruise-ctl-enabled`, `cruise-ctl-fallback-proposal-duration`, `cruise-ctl-min-view-duration`, `cruise-ctl-max-view-duration`, and `network-id-provider-blocklist`. The `stop-at-height` command can also crash an execution node at an attacker-chosen block height.

### Impact Explanation

An unauthenticated attacker who can reach the admin HTTP port can:

- **Set `consensus-required-approvals-for-sealing` to 0** on a consensus node, causing it to construct seals without waiting for any verification approvals. This degrades the safety guarantee of the sealing pipeline on that node.
- **Disable the cruise control** (`cruise-ctl-enabled=false`) or set an extreme `cruise-ctl-fallback-proposal-duration`, disrupting block timing and liveness on the targeted consensus node.
- **Manipulate `network-id-provider-blocklist`** to eject legitimate staked nodes from the targeted node's view, partitioning it from the rest of the network.
- **Trigger `stop-at-height`** to crash an execution node at a chosen height, halting execution on that node.

The first two impacts directly affect consensus safety and liveness parameters that are supposed to be under operator/governance control, not freely settable by any network peer.

### Likelihood Explanation

The admin server is not started by default (`AdminAddr == NotSet`). However:

- The `cmd/ledger/README.md` documentation explicitly demonstrates binding to `0.0.0.0:9003`.
- The benchnet Kubernetes configuration exposes port 9002 as a named `containerPort` (`admin`), making it reachable within the cluster network.
- The localnet README documents port-mapping the admin port to a host port accessible via `curl`.
- Any deployment that binds `--admin-addr` to a non-loopback address without also configuring mutual TLS is fully exposed.

Because TLS is opt-in and the documentation normalizes binding to `0.0.0.0`, real deployments are likely to expose the unauthenticated admin endpoint to at least the container/cluster network, where a compromised co-tenant or malicious observer node could reach it.

### Recommendation

1. **Require authentication by default.** The HTTP server should reject all requests unless the caller presents a valid credential. Mutual TLS should be the default, not an opt-in.
2. **Enforce TLS when `--admin-addr` is set to a non-loopback address.** If the bind address is not `127.0.0.1`/`::1`, the node should refuse to start without TLS credentials configured.
3. **Add a gRPC authentication interceptor** so that even the Unix-socket path enforces identity checks if the socket permissions are ever relaxed.
4. **Separate read-only commands from state-mutating commands** and require stronger authentication for the latter.

### Proof of Concept

```bash
# No credentials required. Any host that can reach port 9002 can zero out
# the sealing approval requirement on a consensus node:
curl http://<consensus-node>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config",
       "data": {"consensus-required-approvals-for-sealing": 0}}'

# Or crash an execution node at the next block:
curl http://<execution-node>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "stop-at-height",
       "data": {"height": <next_height>, "crash": true}}'
```

Both calls succeed with HTTP 200 and no authentication challenge when TLS is not configured. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** admin/command_runner.go (L188-215)
```go
func (r *CommandRunner) runAdminServer(ctx irrecoverable.SignalerContext) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	r.logger.Info().Msg("admin server starting up")

	// Remove stale socket file from previous run (e.g. after container/process restart)
	if _, err := os.Stat(r.grpcAddress); err == nil {
		if removeErr := os.Remove(r.grpcAddress); removeErr != nil {
			r.logger.Warn().Err(removeErr).Str("socket", r.grpcAddress).Msg("failed to remove stale admin socket")
		}
	}

	listener, err := net.Listen("unix", r.grpcAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on admin server address: %w", err)
	}

	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(r.maxMsgSize),
		grpc.MaxSendMsgSize(r.maxMsgSize),
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAdminServer(grpcServer, NewAdminServer(r))
```

**File:** admin/command_runner.go (L256-270)
```go
	r.workersFinished.Go(func() {
		r.workersStarted.Done()

		// Start HTTP server (and proxy calls to gRPC server endpoint)
		var err error
		if r.tlsConfig == nil {
			err = httpServer.ListenAndServe()
		} else {
			err = httpServer.ListenAndServeTLS("", "")
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.logger.Err(err).Msg("HTTP server encountered error")
			ctx.Throw(err)
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

**File:** cmd/scaffold.go (L732-783)
```go
func (fnb *FlowNodeBuilder) EnqueueAdminServerInit() error {
	if fnb.AdminAddr == NotSet {
		return nil
	}

	if (fnb.AdminCert != NotSet || fnb.AdminKey != NotSet || fnb.AdminClientCAs != NotSet) &&
		!(fnb.AdminCert != NotSet && fnb.AdminKey != NotSet && fnb.AdminClientCAs != NotSet) {
		return fmt.Errorf("admin cert / key and client certs must all be provided to enable mutual TLS")
	}

	// create the updatable config manager
	fnb.RegisterDefaultAdminCommands()
	fnb.Component("admin server", func(node *NodeConfig) (module.ReadyDoneAware, error) {
		// set up all admin commands
		for commandName, commandFunc := range fnb.adminCommands {
			command := commandFunc(fnb.NodeConfig)
			fnb.adminCommandBootstrapper.RegisterHandler(commandName, command.Handler)
			fnb.adminCommandBootstrapper.RegisterValidator(commandName, command.Validator)
		}

		opts := []admin.CommandRunnerOption{
			admin.WithMaxMsgSize(int(fnb.AdminMaxMsgSize)),
		}

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

		runner := fnb.adminCommandBootstrapper.Bootstrap(fnb.Logger, fnb.AdminAddr, opts...)

		return runner, nil
	})

	return nil
}
```

**File:** cmd/consensus/main.go (L229-248)
```go
		Module("updatable sealing config", func(node *cmd.NodeConfig) error {
			setter, err := updatable_configs.NewSealingConfigs(
				requiredApprovalsForSealConstruction,
				requiredApprovalsForSealVerification,
				chunkAlpha,
				emergencySealing,
			)
			if err != nil {
				return err
			}

			// update the getter with the setter, so other modules can only get, but not set
			getSealingConfigs = setter

			// admin tool is the only instance that have access to the setter interface, therefore, is
			// the only module can change this config
			err = node.ConfigManager.RegisterUintConfig("consensus-required-approvals-for-sealing",
				setter.RequireApprovalsForSealConstructionDynamicValue,
				setter.SetRequiredApprovalsForSealingConstruction)
			return err
```
