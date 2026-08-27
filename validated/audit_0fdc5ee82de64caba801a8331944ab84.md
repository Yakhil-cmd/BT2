### Title
Unbounded HTTP endpoint accepts unlimited concurrent/slow connections with no timeouts or request-in-flight limits, enabling resource-exhaustion DoS - ([File: main.go])

### Summary
`git-sync`'s optional `--http-bind` HTTP endpoint (liveness `/`, `/metrics`, `/debug/pprof/*`) is started via a bare `http.Serve(ln, mux)` call, without any `http.Server{}` configuration for `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, `IdleTimeout`, or `MaxHeaderBytes`, and the Prometheus handler is created with `promhttp.Handler()` which uses zero-valued `HandlerOpts` (`MaxRequestsInFlight: 0`, `Timeout: 0`). This is structurally analogous to the Nethermind RLPx report: the server has no mechanism to bound or disconnect misbehaving/excessive clients before resource exhaustion occurs.

### Finding Description
The HTTP endpoint is set up in `main.go`: [1](#0-0) 

Key issues:
1. `http.Serve(ln, mux)` uses Go's zero-value default server settings — no `ReadTimeout`/`ReadHeaderTimeout`/`WriteTimeout`/`IdleTimeout` are set, so a client can open a TCP connection, send headers extremely slowly (or not at all), and hold the connection open indefinitely, consuming a goroutine and file descriptor per connection with no server-side eviction (classic slow-loris pattern) — the process never disconnects the client on its own.
2. `mux.Handle("/metrics", promhttp.Handler())` uses default `HandlerOpts{}` [2](#0-1)  — since `MaxRequestsInFlight` defaults to 0 ("no limit is applied") and `Timeout` defaults to 0 ("No timeout is applied"), an unlimited number of concurrent `/metrics` scrapes can run simultaneously, each performing a full `Gather()` over the registry, which is CPU/memory expensive when repeated at volume.
3. Depending on deployment, `--http-bind` can be set to listen on `0.0.0.0` rather than `127.0.0.1` (the flag help simply documents both options), meaning the endpoint may be reachable beyond localhost/pod-local traffic (e.g., in a shared network namespace or misconfigured binding), giving a remote unauthenticated party the ability to mount this attack.

This mirrors the reported bug class: absence of any cap on the number of accepted, unauthenticated protocol interactions (RLPx auth packets there, raw HTTP connections/requests here) before the server takes protective action, allowing an attacker to drive CPU usage up and hold resources with comparatively minimal traffic.

### Impact Explanation
Sustained abuse of the endpoint (many slow/idle connections, or many concurrent `/metrics` scrapes) can exhaust goroutines, file descriptors, and CPU on the `git-sync` process. Because `git-sync`'s core sync loop runs in the same process as the HTTP server, resource exhaustion here can degrade or stall the sync loop itself, resulting in persistent sync denial for the sidecar — consumers relying on the `--link` symlink would stop receiving updates. This aligns with the accepted impact category of "persistent sync denial."

### Likelihood Explanation
Requires `--http-bind` to be enabled (and, more severely, bound to a non-loopback address or otherwise reachable network) — this is an explicit, documented, commonly-used flag (`--http-metrics`, `--http-pprof` are common in Kubernetes deployments for liveness/metrics scraping) [3](#0-2) , so the endpoint is frequently enabled. No credentials or authentication are required for any request to `/`, `/metrics`, or `/debug/pprof/*`, so any network-reachable, unprivileged client can attempt the abuse.

### Recommendation
Configure an explicit `http.Server` with sane `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` values instead of the bare `http.Serve(ln, mux)` call, and use `promhttp.HandlerFor` with a non-zero `MaxRequestsInFlight` and `Timeout` in `HandlerOpts` for `/metrics`. Consider also documenting/defaulting `--http-bind` to loopback-only unless explicitly overridden.

### Proof of Concept
1. Start `git-sync` with `--http-bind=:8080 --http-metrics`.
2. From an unprivileged network client, open many TCP connections to `:8080` and either (a) send partial HTTP headers very slowly and never complete them, or (b) issue a large number of concurrent `GET /metrics` requests.
3. Observe goroutine/file-descriptor growth and CPU usage climbing on the `git-sync` process, with no connections being proactively dropped by the server, since no timeouts or in-flight limits are configured in [4](#0-3)  or [5](#0-4) .

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

**File:** vendor/github.com/prometheus/client_golang/prometheus/promhttp/http.go (L94-108)
```go
func HandlerForTransactional(reg prometheus.TransactionalGatherer, opts HandlerOpts) http.Handler {
	var (
		inFlightSem chan struct{}
		errCnt      = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "promhttp_metric_handler_errors_total",
				Help: "Total number of internal errors encountered by the promhttp metric handler.",
			},
			[]string{"cause"},
		)
	)

	if opts.MaxRequestsInFlight > 0 {
		inFlightSem = make(chan struct{}, opts.MaxRequestsInFlight)
	}
```
