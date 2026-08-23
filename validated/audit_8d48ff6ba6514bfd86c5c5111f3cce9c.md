### Title
Unbounded pagination loop in `preloadClosedByPullRequestsReferences` allows a malicious host to hang `gh issue view` - ([File: pkg/cmd/issue/view/http.go])

### Summary
`preloadClosedByPullRequestsReferences` in `pkg/cmd/issue/view/http.go` fetches additional pages of an issue's `closedByPullRequestsReferences` connection in a `for` loop whose only exit condition is the server-supplied `PageInfo.HasNextPage` field going false. A host controlling the GraphQL responses (e.g. a GitHub Enterprise Server or proxy the victim has configured `gh` to talk to) can keep returning `HasNextPage: true` forever, causing `gh issue view` to loop indefinitely making outbound requests.

### Finding Description
The function is called when `viewRun` determines the requested field set includes `closedByPullRequestsReferences` (via `lookupFields.Contains(...)` in `pkg/cmd/issue/view/view.go`). It only checks `issue.ClosedByPullRequestsReferences.PageInfo.HasNextPage` once before entering the loop, and inside the loop the termination check [1](#0-0) 
relies exclusively on `query.Node.Issue.ClosedByPullRequestsReferences.PageInfo.HasNextPage` and advances `endCursor` from server-returned data with no maximum iteration count, no timeout, and no bound on total nodes accumulated in `issue.ClosedByPullRequestsReferences.Nodes`. This mirrors the identical unbounded pattern in the sibling function `preloadIssueComments` in the same file [2](#0-1) .

Since `PageInfo.HasNextPage` and `EndCursor` are entirely attacker-controlled response fields (there is no client-side cap on page count or elapsed time), a malicious/compromised GraphQL endpoint can respond with `hasNextPage: true` and a valid-looking cursor on every request, keeping the client looping and issuing repeated HTTP requests indefinitely, each of which can also carry an arbitrarily large `Nodes` payload, driving unbounded memory growth in `issue.ClosedByPullRequestsReferences.Nodes`.

### Impact Explanation
This is a client-side resource-exhaustion / denial-of-service condition against the `gh` CLI process: the command never terminates, consumes increasing memory, and ties up the invoking process/CI job indefinitely. It requires the victim to have `gh` pointed at (or the request routed to) a host the attacker controls the responses for — this matches the allowed attacker model ("controls responses from a host the victim points gh at"). This maps to a low/moderate-severity availability impact class (client hang / resource exhaustion), not remote code execution or credential exfiltration.

### Likelihood Explanation
Exploitation requires the victim's `gh` to be directed at an attacker-influenced GraphQL endpoint (e.g., a malicious or compromised GHES instance configured via `GH_HOST`/`gh auth login --hostname`, or a proxy the victim was tricked into using) and for the issue being viewed to include the `closedByPullRequestsReferences` field in the requested lookup fields. Given that precondition, the exploit is trivial and fully repeatable — the malicious server simply always returns `hasNextPage: true`.

### Recommendation
Add a hard upper bound on pagination iterations (and/or total nodes fetched) in `preloadClosedByPullRequestsReferences` (and the identical pattern in `preloadIssueComments`), e.g. cap the loop at a fixed number of pages, enforce an overall request/time budget, and abort with an error once the cap is exceeded instead of trusting the server-supplied `HasNextPage` value indefinitely.

### Proof of Concept
Go test using `httpmock`:
1. Construct an `api.Issue` with `ClosedByPullRequestsReferences.PageInfo.HasNextPage = true` and a valid `EndCursor`.
2. Register an `httpmock.Registry` responder for the `closedByPullRequestsReferences` GraphQL query that always returns a JSON body with `pageInfo.hasNextPage = true` and a fresh `endCursor` on every call, plus a small `nodes` array.
3. Call `preloadClosedByPullRequestsReferences(client, repo, issue)` in a goroutine with a `context`/timer-based test guard (e.g. `time.AfterFunc` failing the test after N seconds) and assert the function never returns, and that the mock responder's call count keeps increasing without bound — demonstrating the infinite-loop DoS.

### Citations

**File:** pkg/cmd/issue/view/http.go (L33-50)
```go
	for {
		var query response
		err := gql.Query(repo.RepoHost(), "CommentsForIssue", &query, variables)
		if err != nil {
			return err
		}

		comments := query.Node.Issue.Comments
		if comments == nil {
			comments = query.Node.PullRequest.Comments
		}

		issue.Comments.Nodes = append(issue.Comments.Nodes, comments.Nodes...)
		if !comments.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(comments.PageInfo.EndCursor)
	}
```

**File:** pkg/cmd/issue/view/http.go (L76-89)
```go
	for {
		var query response
		err := gql.Query(repo.RepoHost(), "closedByPullRequestsReferences", &query, variables)
		if err != nil {
			return err
		}

		issue.ClosedByPullRequestsReferences.Nodes = append(issue.ClosedByPullRequestsReferences.Nodes, query.Node.Issue.ClosedByPullRequestsReferences.Nodes...)

		if !query.Node.Issue.ClosedByPullRequestsReferences.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Node.Issue.ClosedByPullRequestsReferences.PageInfo.EndCursor)
	}
```
