### Title
Slowloris-style resource exhaustion via unbounded `http.Serve` on `--http-bind` endpoint - ([File: main.go])

### Summary
When `--http-bind` is enabled, git-sync starts an HTTP server with `http.Serve(ln, mux)` using no `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, or `IdleTimeout`. An attacker who can reach the `--http-bind` port can open many slow/idle connections that each hold a goroutine and a file descriptor open indefinitely, degrading the process and potentially starving git operations of file descriptors, stalling sync updates.

### Finding Description
The HTTP endpoint is set up in `main()`: [1](#0-0) 

`net.Listen("tcp", *flHTTPBind)` creates the listener and `http.Serve(ln, mux)` is called directly on the raw `net.Listener` with the default `http.Server` semantics — i.e., no timeouts at all. Go's standard library documents that `http.Serve`/a zero-value `http.Server` has no default read/write/idle timeouts, so a client that connects and sends data extremely slowly (or not at all after the connection is accepted) will keep the accepted connection — and its corresponding per-connection goroutine and file descriptor — alive indefinitely. There is no `MaxHeaderBytes` limit issue here since defaults apply, but the missing `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout` means a slow-header or slow-body/keep-alive client is never forcibly disconnected.

The `/` liveness handler itself is trivial and stateless — it just reads `getRepoReady()` under a mutex and returns 200/503 — so it is not itself a source of blocking: [2](#0-1) [3](#0-2) 

The actual exhaustion vector is purely at the transport layer: an attacker doesn't need to interact meaningfully with the handler logic at all — merely completing a TCP handshake and trickling bytes (or none) is enough to pin a goroutine/fd for the life of the connection, because `http.Serve` never times it out.

This is architecturally separate from the sync loop's `failCount`/`--max-failures` logic and the `repoReady` latch — those govern when the process decides to `os.Exit(1)` on sync errors and when `/` starts returning 200 — but they are not what enables the resource exhaustion. The vulnerability is entirely in the missing timeout configuration on the HTTP listener, which runs concurrently with (not through) the sync loop, at: [4](#0-3) 

If enough connections are opened, the process can exhaust available file descriptors, which are shared with git subprocess operations (`git fetch`, worktree creation, etc.) performed by the sync loop, potentially causing `git.SyncRepo` to fail on fd-dependent syscalls, incrementing `failCount` until `--max-failures` is hit and the process exits, or otherwise stalling.

### Impact Explanation
This matches the "sidecar denial of service" class: an attacker that can merely reach the `--http-bind` TCP port (a normal, documented, always-listening endpoint whenever `--http-bind` is configured — a supported, common Kubernetes liveness-probe configuration) can pin unbounded goroutines/file descriptors in the git-sync process, degrading or halting its ability to perform git operations, and eventually consuming all process file descriptors, which is a hard failure mode for the whole container.

### Likelihood Explanation
- Requires only that the operator has set `--http-bind` (a normal, common, documented configuration used for K8s liveness/startup probes) — not requiring any unusual or non-default flag.
- No authentication is required to connect to this endpoint (it's designed to be reachable by kubelet, i.e., unauthenticated).
- The attack is trivial to mount from any host with network access to the pod's HTTP port (e.g., a co-located pod in the same cluster, matching the stated "unauthenticated in-cluster request" attacker model) — a client simply opens TCP connections and trickles/withholds data.
- No `git` content, credentials, or repo control is even required for this specific vector.

### Recommendation
Configure explicit timeouts and connection limits on the HTTP server instead of using the bare `http.Serve`:
- Use `&http.Server{Handler: mux, ReadHeaderTimeout: ..., ReadTimeout: ..., WriteTimeout: ..., IdleTimeout: ...}` and call `srv.Serve(ln)` (or `srv.ListenAndServe`).
- Consider limiting maximum concurrent connections (e.g., via a limiting listener) and setting `MaxHeaderBytes`.
- These are standard Go hardening measures against Slowloris-style attacks (commonly flagged by gosec rule G112).

### Proof of Concept
Integration-style repro:
1. Start git-sync with `--http-bind=:8080` against any repo.
2. From a separate process, open N (e.g., 1000+) raw TCP connections to `:8080` and send bytes at a very slow rate (e.g., 1 byte per 30s) or not at all after connecting, never closing them.
3. Observe via `/proc/<pid>/fd` (or `netstat`) that goroutine/fd counts climb unbounded and are never reclaimed, while the process's ability to spawn further git subprocesses (which also need fds) degrades; eventually `git.SyncRepo` calls begin failing with fd-exhaustion errors, incrementing `failCount` in the sync loop until `os.Exit(1)` occurs (if `--max-failures` is set) or the process becomes unresponsive.

Expected: the process should either reject or forcibly time out slow/idle connections after a bounded interval (assert connections are closed after `ReadHeaderTimeout`/`IdleTimeout` elapses); currently it does not, since `http.Serve(ln, mux)` at [5](#0-4)  applies no such bound.

### Citations

**File:** main.go (L856-895)
```go
	if *flHTTPBind != "" {
		ln, err := net.Listen("tcp", *flHTTPBind)
		if err != nil {
			log.Error(err, "can't bind HTTP endpoint", "endpoint", *flHTTPBind)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		reasons := []string{}

		// This is a dumb liveliness check endpoint. Currently this checks
		// nothing and will always return 200 if the process is live.
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if !getRepoReady() {
				http.Error(w, "repo is not ready", http.StatusServiceUnavailable)
			}
			// Otherwise success
		})
		reasons = append(reasons, "liveness")

		if *flHTTPMetrics {
			mux.Handle("/metrics", promhttp.Handler())
			reasons = append(reasons, "metrics")
		}

		if *flHTTPprof {
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			reasons = append(reasons, "pprof")
		}

		log.V(0).Info("serving HTTP", "endpoint", *flHTTPBind, "reasons", reasons)
		go func() {
			err := http.Serve(ln, mux)
			log.Error(err, "HTTP server terminated")
			os.Exit(1)
		}()
	}
```

**File:** main.go (L1273-1287)
```go
// repoReady indicates that the repo has been synced.
var readyLock sync.Mutex
var repoReady = false

func getRepoReady() bool {
	readyLock.Lock()
	defer readyLock.Unlock()
	return repoReady
}

func setRepoReady() {
	readyLock.Lock()
	defer readyLock.Unlock()
	repoReady = true
}
```
