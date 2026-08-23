### Title
Uncontrolled resource consumption via unbounded pagination loop driven by attacker-controlled `Link`/`endCursor` values - ([File: pkg/cmd/api/api.go])

### Summary
`gh api --paginate` follows pagination hints (`Link: rel="next"` header for REST, or GraphQL `endCursor`) supplied entirely by the responding server, and loops with no maximum iteration count, no visited-URL tracking, and no cap on accumulated output. A remote host that `gh api` is pointed at (via `--hostname`, a custom GraphQL/REST endpoint, or a GitHub Enterprise Server instance under attacker influence) can keep returning a "next page" indicator forever, causing the `gh` process to loop indefinitely, issue unbounded outbound requests, and grow memory/output without bound — directly analogous to the Monero `get_fee_estimate` report's uncontrolled loop driven by attacker-supplied input.

### Finding Description
In `apiRun`, the pagination loop is:
```go
isFirstPage := true
hasNextPage := true
for hasNextPage {
    resp, err := httpRequest(httpClient, host, method, requestPath, requestBody, requestHeaders)
    ...
    if !isGraphQL {
        requestPath, hasNextPage = findNextPage(resp)
        ...
    }
    ...
    if isGraphQL {
        hasNextPage = endCursor != ""
        ...
    }
}
``` [1](#0-0) 

`findNextPage` simply extracts whatever URL the server places in the `Link` response header with `rel="next"`, with no validation against the requested host or any dedup/limit logic: [2](#0-1) 

Similarly, for GraphQL requests the loop continues as long as the server-supplied `endCursor` string is non-empty: [3](#0-2) 

There is no bound on the number of iterations, no cap on total items/bytes accumulated in `bodyWriter`, and no protection against a server returning a `Link`/`endCursor` value that trivially points back to the same or a freshly-generated "next" page indefinitely. This mirrors the Monero root cause: a value fully controlled by a remote party (`grace_blocks` there; the `Link`/`endCursor` here) is used directly as the continuation condition of an otherwise-unbounded loop, with no server- or client-side sanity check on how many iterations are allowed.

The same unbounded "follow whatever the server says is next" pattern also exists in other pagination call sites (`pkg/search/searcher.go` `Code()`, `internal/codespaces/api/api.go` `findNextPage`), but those are all internally capped by a caller-supplied `limit`. `gh api --paginate`, by contrast, has no such cap — pagination continues as long as the server keeps advertising a next page, with the only bound being memory/time.

### Impact Explanation
When `gh api ... --paginate` is pointed at an untrusted or attacker-influenced host (e.g., a malicious GHES-compatible endpoint, or a MITM/compromised host reachable via `--hostname`), the attacker fully controls whether pagination continues by simply always emitting a `Link: <url>; rel="next"` header (REST) or a non-empty `endCursor` (GraphQL). This lets the attacker force the local `gh` process into an effectively infinite loop: continuously issuing outbound HTTP requests, continuously writing to `bodyWriter`/stdout, and consuming unbounded memory and CPU/network resources on the invoking user's machine until it is killed or resources are exhausted. This is a client-side denial-of-service, matching the "Uncontrolled Resource Consumption" weakness class of the reference report, translated into gh's HTTP client / pagination handling.

### Likelihood Explanation
Reaching this requires the user to run `gh api` with `--paginate` against a host that is attacker-controlled or attacker-influenced (custom `--hostname`, a compromised/malicious GHES instance, or a MITM'd connection). This is a normal, documented `gh` usage pattern (pagination is a core, advertised feature), so no privileged access or unusual configuration is needed beyond directing `gh api` at the malicious host — which is plausible in CI pipelines or scripts that parameterize the API host. Likelihood is moderate: it requires the victim to interact with an attacker-influenced host, but no additional trust bypass or credentials are needed.

### Recommendation
- Add a hard upper bound on the number of pagination iterations (and/or total accumulated response size) in `apiRun`'s loop in `pkg/cmd/api/api.go`, independent of what the server reports.
- Track previously-visited `next` URLs / cursors and abort if a cycle or repeated value is detected.
- Consider capping total elapsed time or total bytes written to `bodyWriter` during a `--paginate` session, with a clear user-facing error when the limit is exceeded.

### Proof of Concept
1. Stand up a malicious HTTP server that responds to any GET with `200 OK`, a small JSON body, and a `Link` header of the form: `<http://ATTACKER_HOST/next>; rel="next"` (always pointing to a URL served by the same attacker-controlled server, regardless of path/query).
2. Run: `gh api repos/x/y --hostname ATTACKER_HOST --paginate`.
3. Observe that `gh` loops indefinitely in `apiRun`'s `for hasNextPage { ... }` [4](#0-3) , issuing continuous requests to the attacker server and continuously growing output/memory, with no built-in limit to stop it — the process must be forcibly terminated.

### Citations

**File:** pkg/cmd/api/api.go (L427-466)
```go
	isFirstPage := true
	hasNextPage := true
	for hasNextPage {
		resp, err := httpRequest(httpClient, host, method, requestPath, requestBody, requestHeaders)
		if err != nil {
			return err
		}

		if !isGraphQL {
			requestPath, hasNextPage = findNextPage(resp)
			requestBody = nil // prevent repeating GET parameters
		}

		// Tell optional jsonArrayWriter to start a new page.
		err = startPage(bodyWriter)
		if err != nil {
			return err
		}

		endCursor, err := processResponse(resp, opts, bodyWriter, headersWriter, tmpl, isFirstPage, !hasNextPage)
		if err != nil {
			return err
		}
		isFirstPage = false

		if !opts.Paginate {
			break
		}

		if isGraphQL {
			hasNextPage = endCursor != ""
			if hasNextPage {
				params["endCursor"] = endCursor
			}
		}

		if hasNextPage && opts.ShowResponseHeaders {
			fmt.Fprint(opts.IO.Out, "\n")
		}
	}
```

**File:** pkg/cmd/api/pagination.go (L15-24)
```go
var linkRE = regexp.MustCompile(`<([^>]+)>;\s*rel="([^"]+)"`)

func findNextPage(resp *http.Response) (string, bool) {
	for _, m := range linkRE.FindAllStringSubmatch(resp.Header.Get("Link"), -1) {
		if len(m) > 2 && m[2] == "next" {
			return m[1], true
		}
	}
	return "", false
}
```
