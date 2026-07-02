### Title
Unauthenticated Admin HTTP Server Allows Any Network Peer to Modify the Node Disallow List — (`admin/command_runner.go`, `admin/server.go`)

---

### Summary

The admin HTTP server exposes a `set-config` command that can overwrite or clear the `network-id-provider-blocklist` (the node disallow list). The server has **no caller authentication** when TLS is not configured, which is the default. Any network peer that can reach the admin HTTP port can issue a `set-config` request to clear the disallow list, removing all previously blocked byzantine nodes and allowing them to reconnect to the affected node. The change is persisted to the database and survives restarts.

---

### Finding Description

`admin/command_runner.go` starts two servers: a gRPC server on a Unix socket (local-only) and an HTTP reverse-proxy server on a configurable TCP address. The HTTP server is the externally reachable entry point.

**No authentication is applied to the HTTP server when TLS is absent.** The `runAdminServer` function starts the HTTP server unconditionally:

```go
if r.tlsConfig == nil {
    err = httpServer.ListenAndServe()   // no auth, no TLS
} else {
    err = httpServer.ListenAndServeTLS("", "")
}
``` [1](#0-0) 

TLS (and therefore mutual-certificate authentication) is only configured when the operator explicitly supplies `--admin-cert`, `--admin-key`, and `--admin-client-cas`. If any of those flags are absent, the server runs with no authentication at all:

```go
if node.AdminCert != NotSet {
    // ... load certs, build tls.Config with RequireAndVerifyClientCert ...
    opts = append(opts, admin.WithTLS(config))
}
``` [2](#0-1) 

The gRPC `RunCommand` handler and the `runCommand` dispatcher perform **zero caller-identity checks**:

```go
func (s *adminServer) RunCommand(ctx context.Context, in *pb.RunCommandRequest) (*pb.RunCommandResponse, error) {
    result, err := s.cr.runCommand(ctx, in.GetCommandName(), in.GetData().AsInterface())
    ...
}
``` [3](#0-2) 

The `set-config` command's `Validator` and `Handler` only check that the named config field exists and that the value parses correctly — there is no check on who is calling: [4](#0-3) 

The `network-id-provider-blocklist` config field is registered on every non-observer node and maps directly to `NodeDisallowListWrapper.Update()`:

```go
err = node.ConfigManager.RegisterIdentifierListConfig("network-id-provider-blocklist",
    disallowListWrapper.GetDisallowList, disallowListWrapper.Update)
``` [5](#0-4) 

`Update()` replaces the **entire** disallow list atomically and persists it to the database:

```go
func (w *NodeDisallowListWrapper) Update(disallowList flow.IdentifierList) error {
    b := disallowList.Lookup()
    w.m.Lock()
    defer w.m.Unlock()
    err := w.nodeDisallowListStore.Store(b)   // persisted to DB
    ...
    w.disallowList = b
    w.updateConsumerOracle().OnDisallowListNotification(...)
    return nil
}
``` [6](#0-5) 

Passing an empty list is equivalent to calling `ClearDisallowList()`, which removes every manually blocked node ID from both the in-memory set and the persistent database entry. [7](#0-6) 

---

### Impact Explanation

An unauthenticated caller can:

1. **Clear the entire disallow list** — every node that an operator manually blocked (e.g., a known byzantine execution node or a spam-flooding verification node) is immediately unblocked. The `ConnectionGater` lifts its block and the `PeerManager` re-establishes outbound connections to those nodes.
2. **Replace the disallow list with an arbitrary set** — the attacker can selectively unblock specific nodes while leaving others blocked, or add new nodes to the list (causing targeted network isolation of legitimate peers).
3. **Persist the change across restarts** — because `Update()` writes to the BadgerDB/PebbleDB protocol database, the cleared list survives a node restart, making remediation non-trivial.

The `DisallowListedCauseAdmin` cause is tracked separately from the ALSP automatic cause. Clearing the admin cause does not trigger ALSP re-detection; the ALSP system only re-adds a node after it accumulates fresh misbehavior penalties, giving the re-admitted byzantine node a window to operate.

---

### Likelihood Explanation

- The admin server is started whenever `--admin-addr` is set, which is standard in all production deployments (the README documents it as the normal operational interface).
- TLS is **not** the default; it requires three additional flags. Deployments that omit them — including containerized setups where the admin port is mapped to the host or a shared container network — expose the unauthenticated HTTP endpoint.
- The attack requires only a single unauthenticated HTTP POST, with no credentials, no cryptographic material, and no prior knowledge beyond the node's admin port number.
- The admin port (`9002` by default per the README) is distinct from the public gRPC/REST API ports, but in Docker/Kubernetes environments it is commonly exposed on the container's internal network, reachable by any co-located service or compromised container.

---

### Recommendation

1. **Make TLS mandatory** when `--admin-addr` is set to a non-loopback address. Reject startup if the admin server is bound to a non-localhost address without TLS and client-certificate authentication.
2. **Add a caller-identity check** inside `runCommand` (or as a gRPC interceptor) that verifies the peer certificate even when the HTTP gateway is used, so that authentication is enforced at the command-dispatch layer regardless of transport.
3. **Scope sensitive commands** (those that mutate security state such as `network-id-provider-blocklist`, `consensus-required-approvals-for-sealing`, `stop-at-height`) behind an additional authorization tier separate from read-only commands.

---

### Proof of Concept

An attacker on the same container network (or any host that can reach the admin port) clears the entire disallow list with a single unauthenticated HTTP request:

```bash
# Clear the disallow list — all manually blocked byzantine nodes are immediately unblocked
curl -s http://<node-admin-host>:9002/admin/run_command \
  -H 'Content-Type: application/json' \
  -d '{"commandName": "set-config", "data": {"network-id-provider-blocklist": []}}'
```

Expected response (no authentication required):
```json
{"output": {"newValue": [], "oldValue": ["<previously-blocked-node-id>"]}}
```

The `NodeDisallowListWrapper.Update(nil)` call triggered by this request persists the empty list to the database and fires `OnDisallowListNotification`, causing the `LibP2PNode` to instruct the `ConnectionGater` to lift its block and the `PeerManager` to re-establish connections to all previously blocked nodes. [6](#0-5) [8](#0-7)

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

**File:** admin/command_runner.go (L261-265)
```go
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

**File:** cmd/scaffold.go (L1290-1291)
```go
		err = node.ConfigManager.RegisterIdentifierListConfig("network-id-provider-blocklist",
			disallowListWrapper.GetDisallowList, disallowListWrapper.Update)
```

**File:** admin/server.go (L18-32)
```go
func (s *adminServer) RunCommand(ctx context.Context, in *pb.RunCommandRequest) (*pb.RunCommandResponse, error) {
	result, err := s.cr.runCommand(ctx, in.GetCommandName(), in.GetData().AsInterface())
	if err != nil {
		return nil, err
	}

	value, err := structpb.NewValue(result)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RunCommandResponse{
		Output: value,
	}, nil
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

**File:** network/p2p/cache/node_disallow_list_wrapper.go (L109-113)
```go
// ClearDisallowList purges the set of blocked node IDs. Convenience function
// equivalent to w.Update(nil). No errors are expected during normal operations.
func (w *NodeDisallowListWrapper) ClearDisallowList() error {
	return w.Update(nil)
}
```
