### Title
Unauthenticated Admin HTTP Server Allows Runtime Bypass of Consensus Sealing Verification — (File: `admin/command_runner.go`)

---

### Summary

The Flow node admin server exposes a privileged HTTP/gRPC endpoint that, when TLS is not configured (the default when no cert flags are supplied), accepts commands from any network-reachable caller with zero authentication. An attacker who can reach the admin port can set the `consensus-required-approvals-for-sealing` config to `0` via the `set-config` command. This causes the consensus node's `ApprovalCollector` to immediately seal every execution result without collecting a single verification-node approval, completely bypassing the verification layer.

---

### Finding Description

**Root cause — no authentication by default on the admin HTTP server**

`CommandRunner.runAdminServer` in `admin/command_runner.go` starts two servers:

1. A Unix-socket gRPC server (local only).
2. An HTTP server bound to the address given by `--admin-addr`. [1](#0-0) 

TLS is applied to the HTTP server only when `r.tlsConfig != nil`. That field is populated only if the operator explicitly passes all three of `--admin-cert`, `--admin-key`, and `--admin-client-certs`. [2](#0-1) 

When those flags are absent the server calls `httpServer.ListenAndServe()` — plain HTTP, no authentication, no IP restriction. Any caller that can reach the port can invoke any registered admin command. [3](#0-2) 

**Mutable critical config — `consensus-required-approvals-for-sealing`**

The consensus node registers `consensus-required-approvals-for-sealing` as a dynamically updatable field whose setter is `SetRequiredApprovalsForSealingConstruction`. [4](#0-3) 

`SetConfigCommand.Handler` calls `field.Set(value)` with no caller-identity check. [5](#0-4) 

The setter explicitly allows `0` — the unit test confirms `SetRequiredApprovalsForSealingConstruction(0)` returns no error. [6](#0-5) 

**Immediate seal-without-approval when value is 0**

`NewApprovalCollector` contains an explicit fast-path: when `requiredApprovalsForSealConstruction == 0`, it inserts empty `AggregatedSignature` entries for every chunk and calls `SealResult()` immediately, without waiting for any verification-node approval. [7](#0-6) 

`ChunkApprovalCollector.ProcessApproval` also short-circuits: `chunkApprovals.NumberSignatures() >= 0` is always true, so the first call returns a seal-ready signature regardless of content. [8](#0-7) 

The seal validator reads `RequireApprovalsForSealConstructionDynamicValue()` at validation time, so the lowered value is honoured there too. [9](#0-8) 

---

### Impact Explanation

Once `consensus-required-approvals-for-sealing` is set to `0`, every new execution result is sealed immediately by the consensus node without a single cryptographic approval from any verification node. A malicious or compromised execution node can submit an incorrect execution result (wrong state root, drained accounts, minted tokens) and have it sealed and finalized on-chain with no independent check. This is an unauthorized mutation of a critical protocol security parameter that directly enables on-chain asset loss.

---

### Likelihood Explanation

The admin server is disabled by default (`--admin-addr` is `NotSet`). However, the localnet documentation explicitly states the admin tool is enabled by default for all node types except access nodes, and production operators routinely enable it for operational tooling. TLS is documented as optional. If the admin server is bound to any address reachable from outside the host (e.g., `0.0.0.0:9002`) without TLS, the attack requires only a single unauthenticated HTTP POST. A malicious co-tenant, a compromised network peer, or any entity with access to the node's management network can execute it. [10](#0-9) [11](#0-10) 

---

### Recommendation

1. **Require mTLS when `--admin-addr` is set to any non-loopback address.** Refuse to start the admin server in plaintext mode if the bind address is not `127.0.0.1` / `::1`.
2. **Default `--admin-addr` to `127.0.0.1:9002`** (loopback only) rather than accepting arbitrary addresses without warning.
3. **Add a hard lower bound** in `SetRequiredApprovalsForSealingConstruction` so that the value cannot be set below `1` via the admin command at runtime, even if `0` is permitted at startup for testing.
4. **Log and alert** whenever a security-critical config field (`consensus-required-approvals-for-sealing`) is changed at runtime, so operators can detect unauthorized mutations.

---

### Proof of Concept

```bash
# Consensus node started with: --admin-addr 0.0.0.0:9002  (no TLS flags)
# Attacker (any network-reachable host) runs:

curl -s http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'

# Expected response:
# {"output":{"newValue":0,"oldValue":1}}

# From this point forward, every new ApprovalCollector created by the consensus node
# calls SealResult() immediately on construction (approval_collector.go:70-84),
# sealing execution results with zero verification-node approvals.
# A malicious execution node can now submit an arbitrary execution result
# and have it finalized on-chain without any independent verification.
```

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

**File:** cmd/consensus/main.go (L245-248)
```go
			err = node.ConfigManager.RegisterUintConfig("consensus-required-approvals-for-sealing",
				setter.RequireApprovalsForSealConstructionDynamicValue,
				setter.SetRequiredApprovalsForSealingConstruction)
			return err
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

**File:** module/updatable_configs/sealing_configs_test.go (L26-31)
```go
	err = instance.SetRequiredApprovalsForSealingConstruction(0)
	require.NoError(t, err)

	// value should be updated by SetRequiredApprovalsForSealingConstruction
	newVal := instance.RequireApprovalsForSealConstructionDynamicValue()
	require.Equal(t, uint(0), newVal)
```

**File:** engine/consensus/approvals/approval_collector.go (L68-84)
```go
	// The following code implements a TEMPORARY SHORTCUT: In case no approvals are required
	// to seal an incorporated result, we seal right away when creating the ApprovalCollector.
	if requiredApprovalsForSealConstruction == 0 {
		// The high-level logic is: as soon as we have collected enough approvals, we aggregate
		// them and store them in collector.aggregatedSignatures. If we don't require any signatures,
		// this condition is satisfied right away. Hence, we add aggregated signature for each chunk.
		for i := range numberOfChunks {
			_, err := collector.aggregatedSignatures.PutSignature(i, flow.AggregatedSignature{})
			if err != nil {
				return nil, fmt.Errorf("sealing result %x failed: %w", result.ID(), err)
			}
		}
		err := collector.SealResult()
		if err != nil {
			return nil, fmt.Errorf("sealing result %x failed: %w", result.ID(), err)
		}
	}
```

**File:** engine/consensus/approvals/chunk_collector.go (L28-40)
```go
func (c *ChunkApprovalCollector) ProcessApproval(approval *flow.ResultApproval) (flow.AggregatedSignature, bool) {
	approverID := approval.Body.ApproverID
	if _, ok := c.assignment[approverID]; ok {
		c.lock.Lock()
		defer c.lock.Unlock()
		c.chunkApprovals.Add(approverID, approval.Body.AttestationSignature)
		if c.chunkApprovals.NumberSignatures() >= c.requiredApprovalsForSealConstruction {
			return c.chunkApprovals.ToAggregatedSignature(), true
		}
	}

	return flow.AggregatedSignature{}, false
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

**File:** integration/localnet/README.md (L357-363)
```markdown
# admin tool
The admin tool is enabled by default in localnet for all node type except access node.

For instance, in order to use admin tool to change log level, first find the local port that maps to `9002` which is the admin tool address, if the local port is `6100`, then run:
```
curl localhost:6100/admin/run_command -H 'Content-Type: application/json' -d '{"commandName": "set-log-level", "data": "debug"}'
```
```
