### Title
Unsanitized SSO header value written to stderr allows CR/ANSI injection into gh's own trusted output - (File: pkg/cmd/factory/default.go)

### Summary
`ExtractHeader` copies the raw `X-GitHub-SSO` response header value verbatim into the package-level `ssoHeader` variable with no sanitization. [1](#0-0)  `SSOURL()` extracts a substring of that raw value via a regex that does not exclude control characters, and several call sites print that substring directly to the terminal with `fmt.Fprintf`, without any escaping. [2](#0-1) [3](#0-2) 

### Finding Description
`ExtractHeader` is wired up only for the `X-GitHub-SSO` header via `client.Transport = api.ExtractHeader("X-GitHub-SSO", &ssoHeader)(client.Transport)`. [4](#0-3)  Inside `ExtractHeader`, `res.Header.Get(name)` is stored into `*dest` with no filtering of control characters: [5](#0-4) 

`SSOURL()` then runs `ssoURLRE.FindStringSubmatch(ssoHeader)` where `ssoURLRE = regexp.MustCompile(`\burl=([^;]+)`)`. The negated character class `[^;]` matches any byte except `;`, including `\r`, `\n`, and other ANSI/control sequences, so whatever the server places between `url=` and the next `;` is passed through untouched. [6](#0-5) [7](#0-6) 

That value is subsequently printed unescaped in multiple locations, e.g.:
- `internal/ghcmd/cmd.go`: `fmt.Fprintf(stderr, "Authorize in your web browser:  %s\n", u)` [3](#0-2) 
- `pkg/cmd/api/api.go`: `fmt.Fprintf(opts.IO.ErrOut, "Authorize in your web browser: %s\n", u)` [8](#0-7) 
- `pkg/cmd/status/status.go` passes `factory.SSOURL()` into `addAuthError`. [9](#0-8) 

None of these writers go through the response-body sanitization path used elsewhere for raw bodies (`iostreams.CopyGuardedContent`, which explicitly guards against binary/escape-sequence output for stdout bodies). [10](#0-9)  Header values, unlike the request-writing path (which is validated via `httpguts.ValidHeaderFieldValue` when *sending* headers), are not validated for embedded control bytes when *parsing* incoming responses, so a value containing a lone `\r` (not immediately followed by `\n`, so it doesn't terminate the HTTP header line) can survive intact through Go's `net/textproto` line-based header parsing and reach the terminal untouched.

An attacker who controls the HTTP responses of a host the victim points `gh` at (e.g., a malicious/compromised GitHub Enterprise-style endpoint, matching the allowed threat model in this audit) can therefore return:
```
X-GitHub-SSO: required; url=https://real-looking-url\rATTACKER TEXT; another
```
causing the printed "Authorize in your web browser: ..." line to be overwritten by attacker-controlled text via the embedded carriage return.

### Impact Explanation
This allows the attacker to spoof the single-line "Authorize in your web browser: `<url>`" message that `gh` prints on 401/403 SSO-enforcement errors, since the carriage return repositions the terminal cursor to redraw that line. This is a real terminal-output spoofing primitive matching "Terminal output spoofing" but it is narrower than the "credential prompt forgery" scenario implied by the audit question: the SSO/`ExtractHeader` path only feeds this one diagnostic line via `fmt.Fprintf`, and does not intersect with `gh`'s interactive token-entry prompt, which is rendered through the separate `prompter`/survey library rather than through `ExtractHeader`/`SSOURL`. So the concretely reachable impact via this exact function is limited to spoofing/overwriting gh's own informational stderr text (and potentially injecting further ANSI escape sequences, since no character is filtered besides `;`), not directly capturing credentials typed by the user.

### Likelihood Explanation
Requires the attacker to control (or man-in-the-middle-independently operate) an HTTP endpoint the victim's `gh` is configured to talk to and have it return a crafted `X-GitHub-SSO` header on a request that triggers the SSO/401 error-reporting code path. This is a narrower precondition than "any repo/remote/host string" — it needs response-header control specifically, not just a repo/ref/file name. Given that, exploitability is moderate/high for victims using custom GHES hosts, but low for the generic "attacker publishes a repo name" scenario described generically in the question.

### Recommendation
Sanitize `ssoHeader`/the extracted URL before printing: strip or reject control characters (`\r`, `\n`, ESC) from the `X-GitHub-SSO` header value in `ExtractHeader` or in `SSOURL()` before it is used in any `fmt.Fprintf` to a terminal, and/or route all such externally-sourced strings through the same escape-sequence-guarding helper (`iostreams.CopyGuardedContent`/equivalent) used for API response bodies.

### Proof of Concept
```go
func TestSSOURL_CRInjection(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Simulate a malicious/compromised host injecting a raw CR into the header value.
        w.Header().Set("X-GitHub-SSO", "required; url=https://good.example\rFORGED: paste your GitHub token: ; another")
        w.WriteHeader(http.StatusForbidden)
    }))
    defer ts.Close()

    cfg := config.NewMockConfig()
    ios, _, _, _ := iostreams.Test()
    client, _ := factory.HttpClientFunc(func() (gh.Config, error) { return cfg, nil }, ios, "v1.2.3", "", &telemetry.NoOpService{})()
    req, _ := http.NewRequest("GET", ts.URL, nil)
    client.Do(req)

    u := factory.SSOURL()
    assert.Contains(t, u, "\r") // demonstrates CR survives extraction, contrary to the expected invariant
}
```
Expected (failing) assertion per the audit's invariant: `assert.NotContains(t, u, "\r")` — this currently fails, confirming the raw carriage return is preserved and would reach `fmt.Fprintf(stderr, "Authorize in your web browser: %s\n", u)` unsanitized.

### Citations

**File:** api/http_client.go (L173-187)
```go
// ExtractHeader extracts a named header from any response received by this client and,
// if non-blank, saves it to dest.
func ExtractHeader(name string, dest *string) func(http.RoundTripper) http.RoundTripper {
	return func(tr http.RoundTripper) http.RoundTripper {
		return &funcTripper{roundTrip: func(req *http.Request) (*http.Response, error) {
			res, err := tr.RoundTrip(req)
			if err == nil {
				if value := res.Header.Get(name); value != "" {
					*dest = value
				}
			}
			return res, err
		}}
	}
}
```

**File:** pkg/cmd/factory/default.go (L23-24)
```go
var ssoHeader string
var ssoURLRE = regexp.MustCompile(`\burl=([^;]+)`)
```

**File:** pkg/cmd/factory/default.go (L206-206)
```go
		client.Transport = api.ExtractHeader("X-GitHub-SSO", &ssoHeader)(client.Transport)
```

**File:** pkg/cmd/factory/default.go (L291-302)
```go
// SSOURL returns the URL of a SAML SSO challenge received by the server for clients that use ExtractHeader
// to extract the value of the "X-GitHub-SSO" response header.
func SSOURL() string {
	if ssoHeader == "" {
		return ""
	}
	m := ssoURLRE.FindStringSubmatch(ssoHeader)
	if m == nil {
		return ""
	}
	return m[1]
}
```

**File:** internal/ghcmd/cmd.go (L241-243)
```go
		} else if u := factory.SSOURL(); u != "" {
			// handles organization SAML enforcement error
			fmt.Fprintf(stderr, "Authorize in your web browser:  %s\n", u)
```

**File:** pkg/cmd/api/api.go (L530-540)
```go
		// A raw non-JSON body is the only response the transport does not sanitize.
		// It is faithful byte output, so binary bound for a terminal and text
		// carrying escape sequences are refused; the opt-out flag and discarded
		// output stream verbatim.
		if !isJSON && !opts.AllowEscapeSequences && bodyWriter != io.Discard {
			err = iostreams.CopyGuardedContent(bodyWriter, responseBody, opts.IO.IsStdoutTTY())
			if binErr, ok := errors.AsType[iostreams.BinaryTerminalError](err); ok {
				err = fmt.Errorf("%w; redirect or pipe stdout to save it, or pass --allow-escape-sequences to output it anyway", binErr)
			} else if errors.Is(err, iostreams.ErrEscapeSequence) {
				err = errors.New("the response contains terminal escape sequences; pass --allow-escape-sequences to output it anyway")
			}
```

**File:** pkg/cmd/api/api.go (L557-558)
```go
		if u := factory.SSOURL(); u != "" {
			fmt.Fprintf(opts.IO.ErrOut, "Authorize in your web browser: %s\n", u)
```

**File:** pkg/cmd/status/status.go (L296-298)
```go
						switch httpStatusCode {
						case 403:
							s.addAuthError(httpErr.Message, factory.SSOURL())
```
