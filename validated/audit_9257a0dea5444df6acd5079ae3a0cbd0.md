### Title
Server-Side Request Forgery via unrestricted HTTP redirect following in webhook/GitHub-App token requests - (File: pkg/hook/webhook.go, main.go)

### Summary
git-sync's webhook notification hook and its GitHub App token-refresh routine issue outbound HTTP requests using `http.DefaultClient`, which follows HTTP redirects (up to Go's default limit of 10) without any restriction. If the configured `--webhook-url` endpoint (or, for the GitHub App flow, `--github-base-url`) is compromised, DNS-rebound, or otherwise made to respond with a redirect, git-sync will automatically issue a second request to whatever address is supplied in the `Location` header — including internal-only addresses (e.g., cloud metadata endpoints, local admin APIs, or other services reachable from the git-sync pod/host). This mirrors the price-feeder SSRF pattern exactly: an external endpoint that the tool trusts is turned into a redirector to internal infrastructure.

### Finding Description
`Webhook.Do` in [1](#0-0)  builds a request to the operator-configured `--webhook-url` and sends it with `http.DefaultClient.Do(req)`, with no `CheckRedirect` override. The Go standard library's default `http.Client` behavior is to transparently follow redirect responses (301/302/303/307/308) to the `Location` header value.

Likewise, `RefreshGitHubAppToken` in main.go performs the GitHub App installation-token exchange the same way — building a request against `--github-base-url` and calling `http.DefaultClient.Do(req)` with no redirect restriction: [2](#0-1) .

Notably, git-sync's own codebase already recognizes and mitigates this exact class of bug elsewhere: `CallAskPassURL` explicitly builds a client with `CheckRedirect` returning `http.ErrUseLastResponse` to stop redirects from being followed: [3](#0-2) . This demonstrates the fix pattern is known but was not applied consistently to the webhook and GitHub App token clients.

The webhook hook is fired automatically whenever a new hash is synced (including on startup when the root already matches), asynchronously from the main sync loop: [4](#0-3) , and is wired up in `main()` when `--webhook-url` is set: [5](#0-4) . This satisfies the "exec/web hooks" reachable surface explicitly called out as in-scope: every successful sync (which can be driven by an attacker who controls content/refs in the synced repository, causing repeated syncs/hook invocations) triggers this vulnerable outbound call.

### Impact Explanation
If the webhook target (or GitHub base URL) is redirected to an internal address, git-sync — running with network access inside its pod/host (e.g., in Kubernetes, with access to cluster-internal services or the instance metadata service) — will issue a request to that internal address on the attacker's behalf. Depending on what is reachable, this can be used to:
- Reach internal-only services and metadata endpoints (SSRF pivot).
- For the GitHub App path, potentially replay the `Authorization: Bearer <jwt>` and other headers to a same-host redirect target, risking token exposure to an unintended path/service.

This matches the accepted impact categories of credential/token disclosure and enabling unauthorized requests to restricted internal services.

### Likelihood Explanation
Likelihood is moderate: it requires the operator-configured webhook or GitHub base endpoint to be compromised, DNS-rebound, or otherwise attacker-influenced (analogous to "attacker gains control over the API" in the original report), combined with git-sync continuing to fire its hooks on every sync cycle — a condition an attacker who can push to the synced repository can trigger repeatedly and predictably.

### Recommendation
Apply the same mitigation already used in `CallAskPassURL` — configure `CheckRedirect` (e.g., return `http.ErrUseLastResponse`, or explicitly deny redirects to link-local/loopback/metadata address ranges) — on the HTTP clients used in `Webhook.Do` (`pkg/hook/webhook.go`) and `RefreshGitHubAppToken` (`main.go`), rather than relying on `http.DefaultClient`'s default redirect-following behavior.

### Proof of Concept
1. Configure git-sync with `--webhook-url=http://attacker-controlled-or-compromised-host/hook`.
2. Have that host respond to the webhook POST with `HTTP/1.1 302 Found` and `Location: http://169.254.169.254/latest/meta-data/` (or any internal service address reachable from the git-sync pod).
3. Trigger a sync (e.g., attacker pushes a new commit to the tracked ref, causing a new hash to sync).
4. `Webhook.Do` (`pkg/hook/webhook.go:59-75`) calls `http.DefaultClient.Do(req)`, which transparently follows the redirect and issues a GET/POST to the internal address, disclosing whatever data that internal service returns or performing an unintended action against it — exactly as in the original price-feeder SSRF scenario.

### Citations

**File:** pkg/hook/webhook.go (L58-75)
```go
// Do calls webhook.url, implements Hook.Do.
func (w *Webhook) Do(ctx context.Context, hash string) error {
	req, err := http.NewRequest(w.method, w.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Gitsync-Hash", hash)

	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	req = req.WithContext(ctx)

	w.log.V(0).Info("sending webhook", "hash", hash, "url", w.url, "method", w.method, "timeout", w.timeout)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
```

**File:** main.go (L897-916)
```go
	// Startup webhooks goroutine
	var webhookRunner *hook.HookRunner
	if *flWebhookURL != "" {
		log := log.WithName("webhook")
		webhook := hook.NewWebhook(
			*flWebhookURL,
			*flWebhookMethod,
			*flWebhookStatusSuccess,
			*flWebhookTimeout,
			log,
		)
		webhookRunner = hook.NewHookRunner(
			webhook,
			*flWebhookBackoff,
			hook.NewHookData(),
			log,
			*flOneTime,
		)
		go webhookRunner.Run(context.Background())
	}
```

**File:** main.go (L2133-2141)
```go
func (git *repoSync) CallAskPassURL(ctx context.Context) error {
	git.log.V(3).Info("calling auth URL to get credentials")

	var netClient = &http.Client{
		Timeout: time.Second * 1,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
```

**File:** main.go (L2232-2246)
```go
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
```

**File:** pkg/hook/hook.go (L122-156)
```go
// Send sends hash to hookdata.
func (r *HookRunner) Send(hash string) {
	r.data.send(hash)
}

// Run waits for trigger events from the channel, and run hook when triggered.
func (r *HookRunner) Run(ctx context.Context) {
	var lastHash string

	// Wait for trigger from hookData.Send
	for range r.data.events() {
		// Retry in case of error
		for {
			// Always get the latest value, in case we fail-and-retry and the
			// value changed in the meantime.  This means that we might not send
			// every single hash.
			hash := r.data.get()
			if hash == lastHash {
				break
			}

			if err := r.hook.Do(ctx, hash); err != nil {
				r.log.Error(err, "hook failed", "hash", hash, "retry", r.backoff)
				updateHookRunCountMetric(r.hook.Name(), "error")
				// don't want to sleep unnecessarily terminating anyways
				r.sendOneTimeResultAndTerminate(false)
				time.Sleep(r.backoff)
			} else {
				updateHookRunCountMetric(r.hook.Name(), "success")
				lastHash = hash
				r.sendOneTimeResultAndTerminate(true)
				break
			}
		}
	}
```
