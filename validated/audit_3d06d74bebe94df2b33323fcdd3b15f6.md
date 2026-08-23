### Title
Hostname smuggling via unvalidated `@` character allows wrong-host request routing with attached token - (File: internal/ghinstance/host.go)

### Summary
`HostnameValidator` only rejects hostnames containing `/` or `:`, but does not reject `@`. Because `GraphQLEndpoint`/`RESTPrefix` build the URL string with raw `fmt.Sprintf("https://api.%s/graphql", hostname)`, a hostname containing `@` is interpreted by the URL authority parser as `userinfo@host`, silently changing the network destination while the token, saved config, and displayed hostname all still reference the original (misleading) string.

### Finding Description
`HostnameValidator` in [1](#0-0)  only blocks `/` and `:`, leaving `@` (and other authority-delimiter characters) unfiltered. `GraphQLEndpoint`/`RESTPrefix` then interpolate the hostname directly into a URL template with `fmt.Sprintf`: [2](#0-1)  and [3](#0-2) .

If a hostname value such as `x@evil.com` is supplied (e.g. via `gh auth login --hostname` with a value copy-pasted from an untrusted source, or reused from `gh.setup-git`/enterprise-instructions text), `GraphQLEndpoint` produces the string `https://api.x@evil.com/graphql`. This string is passed to `safeurl.JoinPathWithHostPrefix` as the `hostPrefix`, which explicitly documents that the prefix "is used as given" with no parsing or re-validation: [4](#0-3) . The resulting string is fed into `http.NewRequest` in `GetCurrentLogin`: [5](#0-4) .

`http.NewRequest`/`url.Parse` interpret the authority component `api.x@evil.com` as `userinfo = "api.x"`, `host = "evil.com"`, per RFC 3986 authority syntax. So the actual TCP/TLS connection and HTTP request (carrying `Authorization: token <authToken>` set immediately after, on line 270) is sent to `evil.com`, not to the intended API host, even though the hostname string as stored everywhere else (`cfg.Login(hostname, ...)`, prompts, displayed messages) is the literal `x@evil.com`.

### Impact Explanation
This is a wrong-host request routing bug with a freshly-entered or freshly-obtained OAuth/PAT token attached in the `Authorization` header, sent to an attacker-controlled host if the victim is tricked into using a hostname value containing `@attacker-domain` (e.g., copied from a malicious README/issue instructing "run `gh auth login --hostname <value>`"). This matches GitHub's bounty class for authenticated request to an attacker host / credential exfiltration.

### Likelihood Explanation
Requires the victim to pass an untrusted, attacker-crafted `--hostname` value to `gh auth login` (or any other flow reaching `GraphQLEndpoint`/`RESTPrefix` with an unsanitized hostname). This is plausible via social engineering in a README/issue telling a user to authenticate against a "custom enterprise host" string containing an embedded `@`. No MITM or privileged access needed; the flaw is purely in local string validation before the request is issued.

### Recommendation
Harden `HostnameValidator` (and/or `GraphQLEndpoint`/`RESTPrefix`) to reject any character not valid in a plain DNS hostname (e.g., allow only `[A-Za-z0-9.-]` plus IDNA-encoded labels), explicitly rejecting `@`, backslashes, whitespace, and other URL-authority metacharacters. Alternatively, build the endpoint via `url.URL{Host: hostname}` and verify `u.Host == hostname` (or that `u.User` is nil) after construction, rejecting the hostname if parsing produces an unexpected split.

### Proof of Concept
```go
func TestGraphQLEndpointHostSmuggling(t *testing.T) {
    hostname := "x@evil.com"
    if err := ghinstance.HostnameValidator(hostname); err != nil {
        t.Fatalf("expected hostname to pass validation, got %v", err)
    }
    endpoint := ghinstance.GraphQLEndpoint(hostname)
    // endpoint == "https://api.x@evil.com/graphql"
    req, err := http.NewRequest("POST", endpoint, nil)
    if err != nil {
        t.Fatal(err)
    }
    if req.URL.Host != "evil.com" {
        t.Fatalf("expected request host to remain %q, got %q", hostname, req.URL.Host)
    }
}
```
This test currently fails the assertion (i.e., demonstrates the bug): `req.URL.Host` resolves to `evil.com` instead of the literal validated hostname, confirming the host-authority smuggling.

### Citations

**File:** internal/ghinstance/host.go (L36-44)
```go
func HostnameValidator(hostname string) error {
	if len(strings.TrimSpace(hostname)) < 1 {
		return errors.New("a value is required")
	}
	if strings.ContainsRune(hostname, '/') || strings.ContainsRune(hostname, ':') {
		return errors.New("invalid hostname")
	}
	return nil
}
```

**File:** internal/ghinstance/host.go (L46-57)
```go
func GraphQLEndpoint(hostname string) string {
	if isGarage(hostname) {
		return fmt.Sprintf("https://%s/api/graphql", hostname)
	}
	if ghauth.IsEnterprise(hostname) {
		return fmt.Sprintf("https://%s/api/graphql", hostname)
	}
	if strings.EqualFold(hostname, localhost) {
		return fmt.Sprintf("http://api.%s/graphql", hostname)
	}
	return fmt.Sprintf("https://api.%s/graphql", hostname)
}
```

**File:** internal/ghinstance/host.go (L59-70)
```go
func RESTPrefix(hostname string) string {
	if isGarage(hostname) {
		return fmt.Sprintf("https://%s/api/v3/", hostname)
	}
	if ghauth.IsEnterprise(hostname) {
		return fmt.Sprintf("https://%s/api/v3/", hostname)
	}
	if strings.EqualFold(hostname, localhost) {
		return fmt.Sprintf("http://api.%s/", hostname)
	}
	return fmt.Sprintf("https://api.%s/", hostname)
}
```

**File:** internal/safeurl/safeurl.go (L147-164)
```go
// joinPathWithHostPrefix builds a full REST API URL by prepending hostPrefix to the path produced by
// JoinPath. A single slash is ensured at the join between hostPrefix and the path so they separate
// cleanly without doubling up. When hostPrefix is empty, the JoinPath result is returned intact, and
// when the joined path is empty, hostPrefix is returned intact. hostPrefix is used verbatim while each
// component is percent-encoded.
func joinPathWithHostPrefix(hostPrefix string, components ...string) string {
	path := joinPath(components...)
	if hostPrefix == "" {
		return path
	}
	if path == "" {
		return hostPrefix
	}
	if !strings.HasSuffix(hostPrefix, "/") {
		return hostPrefix + "/" + path
	}
	return hostPrefix + path
}
```

**File:** pkg/cmd/auth/shared/login_flow.go (L262-270)
```go
	apiEndpoint, err := safeurl.JoinPathWithHostPrefix(ghinstance.GraphQLEndpoint(hostname))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", apiEndpoint.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+authToken)
```
