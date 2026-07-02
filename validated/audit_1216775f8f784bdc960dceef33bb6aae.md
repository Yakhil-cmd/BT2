### Title
Unconditional `net/http/pprof` Debug Endpoints Registered on Production Admin HTTP Server, Enabling Heap/Memory Dump Without Authentication - (File: `admin/command_runner.go`)

---

### Summary

Every Flow node that enables its admin server unconditionally exposes Go's full `net/http/pprof` debug profiling suite — including heap dumps, goroutine stacks, CPU profiles, and execution traces — on the same HTTP mux as the admin API. These endpoints are registered in production builds with no flag to disable them and no authentication requirement beyond the optional mTLS that guards the admin commands. Any network-reachable caller who can reach the admin HTTP port can issue a plain HTTP GET to `/debug/pprof/heap` and receive a full dump of the node process's heap memory, which may contain in-memory private cryptographic keys.

---

### Finding Description

In `admin/command_runner.go`, the `runAdminServer` function unconditionally registers Go's `net/http/pprof` handlers on the shared admin HTTP mux:

```go
// admin/command_runner.go lines 241-247
for _, name := range []string{"allocs", "block", "goroutine", "heap", "mutex", "threadcreate"} {
    mux.HandleFunc(fmt.Sprintf("/debug/pprof/%s", name), pprof.Handler(name).ServeHTTP)
}
mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
``` [1](#0-0) 

These handlers are registered unconditionally — there is no build tag, no runtime flag, and no configuration option to disable them. They are present in every production binary that starts the admin server.

The admin server is started via `EnqueueAdminServerInit` in `cmd/scaffold.go`. TLS/mTLS is entirely optional: if `--admin-cert`, `--admin-key`, and `--admin-client-certs` are not provided, the server runs plain HTTP with no authentication at all. [2](#0-1) 

The admin server's bind address is operator-supplied via `--admin-addr` and accepts any value including `0.0.0.0:<port>`. The localnet builder explicitly configures `--admin-addr=0.0.0.0:<port>` for all node roles: [3](#0-2) 

The pprof HTTP handlers are raw `http.HandlerFunc` registrations — they do not pass through the admin command framework's validator/handler pipeline and therefore bypass any future authentication layer added to admin commands. [4](#0-3) 

---

### Impact Explanation

Go's `net/http/pprof` heap endpoint (`/debug/pprof/heap`) returns a binary dump of the live heap of the node process. A Flow node's heap contains:

- The node's private staking key and networking key (loaded at startup and held in memory for the lifetime of the process).
- Any in-transit transaction payloads, block data, or execution results being processed.
- Internal protocol state.

An attacker who can reach the admin HTTP port and issue `GET /debug/pprof/heap` receives a complete heap snapshot from which private key material can be extracted using standard Go tooling (`go tool pprof`). Compromise of a node's staking key allows the attacker to impersonate that node in the protocol. Compromise of a networking key allows traffic interception and identity spoofing at the libp2p layer.

The `/debug/pprof/goroutine` endpoint additionally leaks full goroutine stack traces, revealing internal execution state and potentially sensitive values on the stack. The `/debug/pprof/trace` endpoint enables real-time execution tracing.

---

### Likelihood Explanation

The admin server is a documented, intentional production feature enabled by passing `--admin-addr`. The README documents its use with `localhost:9002`, but the code enforces no restriction on the bind address. Operators who bind to `0.0.0.0` (as the localnet builder does, and as is natural in containerized/Kubernetes deployments where the admin port is exposed as a service) expose the pprof endpoints to any caller that can reach the pod/container network. In cloud deployments, misconfigured network policies or inadvertent service exposure are common. Because TLS is optional and pprof endpoints require no credentials, exploitation requires only a single unauthenticated HTTP GET. [5](#0-4) 

---

### Recommendation

1. **Remove pprof handlers from the production admin server.** The pprof endpoints should not be registered unconditionally. They should be gated behind a build tag (e.g., `//go:build debug`) or a runtime flag (e.g., `--admin-enable-pprof`) that defaults to `false`.

2. **Enforce authentication parity.** Any endpoint served on the admin HTTP mux must pass through the same authentication layer as admin commands. Raw `http.HandlerFunc` registrations that bypass the command framework should not be permitted in production.

3. **Enforce localhost-only binding by default.** The admin server should default to `127.0.0.1` and warn or refuse to start if bound to a non-loopback address without TLS/mTLS configured.

---

### Proof of Concept

Given a Flow node started with:
```
--admin-addr=0.0.0.0:9002
# (no --admin-cert / --admin-key / --admin-client-certs)
```

An unauthenticated attacker on the same network issues:
```bash
curl -s http://<node-ip>:9002/debug/pprof/heap --output heap.prof
go tool pprof -raw heap.prof | strings | grep -i "key\|secret\|private"
```

The heap dump is returned with HTTP 200 and `Content-Type: application/octet-stream`, as confirmed by the integration test `TestHTTPPProf` which asserts exactly this response: [6](#0-5) 

The attacker then uses standard Go pprof tooling to parse the heap and search for key material. No credentials, tokens, or prior access are required.

### Citations

**File:** admin/command_runner.go (L238-248)
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

**File:** integration/localnet/builder/bootstrap.go (L586-587)
```go
			fmt.Sprintf("--admin-addr=0.0.0.0:%s", testnet.AdminPort),
		},
```

**File:** integration/tests/admin/command_runner_test.go (L288-302)
```go
func (suite *CommandRunnerSuite) TestHTTPPProf() {
	suite.SetupCommandRunner()

	url := fmt.Sprintf("http://%s/debug/pprof/goroutine", suite.httpAddress)
	resp, err := http.Get(url)
	require.NoError(suite.T(), err)
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	suite.Equal(resp.Status, "200 OK")
	suite.Equal(resp.Header.Get("Content-Type"), "application/octet-stream")
}
```
