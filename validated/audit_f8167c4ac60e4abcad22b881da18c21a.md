### Title
Unbounded HTTP response body read in askpass-url credential handler enables memory-exhaustion DoS - ([File: main.go])

### Summary
The Halborn finding concerns an SSP relay API endpoint accepting unbounded input sizes with no validation, enabling resource-exhaustion attacks. The closest reachable analog in `git-sync` is `repoSync.CallAskPassURL`, which fetches credentials from an operator-configured `--askpass-url` and reads the entire HTTP response body into memory with no size limit before parsing it.

### Finding Description
`CallAskPassURL` issues a GET request to `git.authURL` and, on a non-200 response, reads the full error body with `io.ReadAll(resp.Body)` for the error message, and on a 200 response reads the entire body again with `io.ReadAll(resp.Body)` into `authData` with no `io.LimitReader` or `http.MaxBytesReader` wrapping the response body: [1](#0-0) 

Both reads are unconstrained, so an unbounded response (e.g., from a redirected, compromised, or misbehaving askpass endpoint reachable at the configured URL) is buffered entirely into process memory before any parsing or size check occurs. This mirrors the reported bug class: the endpoint accepts input of unrestricted size and performs no validation before processing it. The parsed `authData` is then naively split on `\n` and `=` with `strings.SplitN` and stored via `git.StoreCredentials`, which pipes the values into `git credential approve` via stdin — again with no length or content sanitization: [2](#0-1) [3](#0-2) 

By contrast, `pkg/hook/webhook.go`'s `Do` method has the identical unbounded-read pattern for webhook responses: [4](#0-3) 

### Impact Explanation
An oversized response from the configured askpass (or webhook) endpoint causes `git-sync` to buffer the entire body in memory with no cap, which can exhaust process memory and crash or degrade the sidecar (denial of service), interrupting the sync loop and thus the atomic-symlink publish contract that consumer containers depend on. This matches the report's "Impact: 3" DoS/resource-exhaustion class, though note the trigger source here is the response from a URL the operator explicitly configures (`--askpass-url` / `--webhook-url`), not an arbitrary unauthenticated network attacker — the strength of this analog depends on that endpoint being reachable/controllable by an untrusted party (e.g., a compromised or spoofable internal auth service, or DNS/network path takeover), which is a materially weaker threat model than the original report's public API.

### Likelihood Explanation
The `--askpass-url` and `--webhook-url` flags are commonly pointed at auxiliary internal services; if that service or the network path to it is attacker-influenceable, exploitation only requires returning an oversized/malformed body — no authentication bypass or complex chain is needed, matching the report's "Likelihood: 3" for a low-complexity resource-exhaustion trigger. However, because the URL itself is operator-configured (not attacker-supplied), this scenario is not directly attacker-triggerable without an additional precondition (compromise of the configured endpoint), which lowers confidence in equivalence to the original finding.

### Recommendation
Wrap response bodies with `io.LimitReader(resp.Body, maxSize)` or `http.MaxBytesReader`-equivalent limits before calling `io.ReadAll` in both `CallAskPassURL` (main.go:2154, 2160) and `Webhook.Do` (pkg/hook/webhook.go:76). Validate that the resulting `username`/`password` values are within reasonable length bounds before passing them to `StoreCredentials`, and reject/log oversized or malformed responses rather than buffering and parsing them unconditionally.

### Proof of Concept
Configure `--askpass-url=http://attacker-controlled-or-compromised-host/creds`; have that host return HTTP 200 with a response body of many gigabytes (or an extremely long single line containing `username=`). `CallAskPassURL` calls `io.ReadAll(resp.Body)` at [5](#0-4)  with no size cap, causing unbounded memory growth in the `git-sync` process on every sync attempt where the askpass URL is consulted.

### Citations

**File:** main.go (L2055-2067)
```go
// StoreCredentials stores a username and password for later use.
func (git *repoSync) StoreCredentials(ctx context.Context, url, username, password string) error {
	git.log.V(1).Info("storing git credential", "url", redactURL(url))
	git.log.V(9).Info("md5 of credential", "url", url, "username", md5sum(username), "password", md5sum(password))

	creds := fmt.Sprintf("url=%v\nusername=%v\npassword=%v\n", url, username, password)
	_, _, err := git.RunWithStdin(ctx, "", creds, "credential", "approve")
	if err != nil {
		return fmt.Errorf("can't configure git credentials: %w", err)
	}

	return nil
}
```

**File:** main.go (L2153-2182)
```go
	if resp.StatusCode != http.StatusOK {
		errMessage, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("auth URL returned status %d, failed to read body: %w", resp.StatusCode, err)
		}
		return fmt.Errorf("auth URL returned status %d, body: %q", resp.StatusCode, string(errMessage))
	}
	authData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("can't read auth response: %w", err)
	}

	username := ""
	password := ""
	for line := range strings.SplitSeq(string(authData), "\n") {
		keyValues := strings.SplitN(line, "=", 2)
		if len(keyValues) != 2 {
			continue
		}
		switch keyValues[0] {
		case "username":
			username = keyValues[1]
		case "password":
			password = keyValues[1]
		}
	}

	if err := git.StoreCredentials(ctx, git.repo, username, password); err != nil {
		return err
	}
```

**File:** pkg/hook/webhook.go (L71-86)
```go
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// If the webhook has a success statusCode, check against it
	if w.success > 0 && resp.StatusCode != w.success {
		return fmt.Errorf("received response code %d expected %d, body: %q", resp.StatusCode, w.success, body)
	}

	w.log.V(1).Info("webhook succeeded", "hash", hash, "status", resp.StatusCode, "headers", resp.Header, "body", body)
```
