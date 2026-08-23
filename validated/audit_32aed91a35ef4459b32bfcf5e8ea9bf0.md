### Title
Unbounded GraphQL pagination loops in `gh` PR/Issue/Org preload paths enable memory-exhaustion DoS against clients targeting attacker-controlled GitHub hosts - ([File: pkg/cmd/pr/shared/finder.go], [File: pkg/cmd/issue/view/http.go], [File: api/queries_org.go], [File: api/queries_projects_v2.go])

### Summary
Several GraphQL "preload more pages" loops in the `gh` CLI follow `pageInfo.hasNextPage`/`endCursor` returned by the target GitHub host with no upper bound on the number of pages fetched or the number of nodes accumulated in memory. A host that the user has configured `gh` to talk to (custom `--hostname`, `GH_HOST`, or a repository URL pointing at a GitHub Enterprise Server the attacker controls) can keep responding `hasNextPage: true` with more synthetic nodes indefinitely, causing the `gh` process to allocate memory without limit until it is OOM-killed. This mirrors the reported libp2p-rendezvous class of bug (CWE-770, allocation of resources without limits/throttling driven by untrusted input) but manifests client-side in `gh` rather than in a Rust p2p server.

### Finding Description
`gh` contains multiple "fetch all pages" helper functions that loop purely based on server-supplied continuation signals, with no cap on iteration count or total collected items:

- `preloadPrReviews` and `preloadPrComments` in `pkg/cmd/pr/shared/finder.go` loop `for { ... if !PageInfo.HasNextPage { break } }`, appending every returned node to `pr.Reviews.Nodes` / `pr.Comments.Nodes` on each iteration. [1](#0-0) [2](#0-1) 

- `preloadIssueComments` and `preloadClosedByPullRequestsReferences` in `pkg/cmd/issue/view/http.go` have the identical unbounded pattern. [3](#0-2) [4](#0-3) 

- `OrganizationProjects` (`api/queries_org.go`) and `OrganizationProjectsV2` (`api/queries_projects_v2.go`) similarly loop forever, appending nodes to an in-memory slice, only stopping when the server reports `HasNextPage: false`. [5](#0-4) [6](#0-5) 

None of these functions impose a maximum page count, a maximum accumulated-node count, or a maximum elapsed time/attempt count — unlike other pagination code in the same codebase (e.g. `listLabels` in `pkg/cmd/label/http.go`, `searchPullRequests` in `pkg/cmd/pr/list/http.go`, or `lister.List` in `pkg/cmd/pr/shared/lister.go`) which all respect a caller-supplied `limit` and break out of the loop once it is reached. [7](#0-6) [8](#0-7) 

Since these calls run against whatever host the GraphQL client is pointed at (`repo.RepoHost()`), a malicious or compromised GitHub Enterprise Server that the victim has configured `gh` to trust — or that a victim is lured into targeting via a crafted repository URL/`--hostname` value — can respond to every page request with `hasNextPage: true` and a fresh batch of synthetic nodes, forcing the unbounded loops to run indefinitely and the node slices to grow without bound.

### Impact Explanation
A single `gh pr view`, `gh issue view`, or organization-project-listing invocation against an attacker-controlled host can exhaust available memory on the invoking machine, causing the `gh` process (and potentially the host system, depending on available memory/swap) to be killed or become unresponsive — a denial-of-service condition analogous to the OOM DoS described in the libp2p-rendezvous advisory, just triggered client-side rather than server-side.

### Likelihood Explanation
Requires the victim to run an ordinary `gh` command (`pr view`, `issue view`, project listing, etc.) against a host under attacker control — e.g. by pointing `--hostname`/`GH_HOST` at an attacker-operated GitHub Enterprise Server, or by being directed to a URL naming such a host. No authentication bypass, MITM, or local access is required; the attacker only needs to operate the GraphQL endpoint that responds to the request, which fits the "attacker-controlled host during a normal gh command" category. Likelihood is moderate: it depends on the user pointing `gh` at a host they don't fully trust, which is a narrower reachable surface than the original unauthenticated network-wide libp2p rendezvous case, but is squarely within accepted analog categories (HTTP client processing of attacker-controlled host responses).

### Recommendation
Add hard caps (e.g., maximum page count and/or maximum total node count) to all "fetch until no more pages" loops that are driven solely by server-supplied `hasNextPage`/`endCursor` values, mirroring the `limit`-aware pagination already used elsewhere in the codebase (`listLabels`, `searchPullRequests`, `lister.List`). Consider also bounding total response bytes/time spent in these preload loops so that a misbehaving or malicious host cannot force unbounded memory growth in the `gh` process.

### Proof of Concept
1. Stand up a mock/malicious GraphQL server implementing the `CommentsForPullRequest` (or `ReviewsForPullRequest`, `OrganizationProjectList`, etc.) query used by `preloadPrComments` / `preloadPrReviews` (`pkg/cmd/pr/shared/finder.go`).
2. Have the mock server always return `pageInfo.hasNextPage: true` with a new `endCursor` and a batch of comment/review nodes on every request, regardless of the `endCursor` supplied.
3. Run `gh pr view <pr-with-many-pages-signalled> --hostname <attacker-host>` (or configure `GH_HOST`) so the client's GraphQL calls hit the malicious server.
4. Observe that `pr.Comments.Nodes` / `pr.Reviews.Nodes` grow without bound as the loop in `preloadPrComments`/`preloadPrReviews` never terminates, and the `gh` process's memory usage climbs until it is killed by the OS OOM killer.

### Citations

**File:** pkg/cmd/pr/shared/finder.go (L464-478)
```go
	for {
		var query response
		err := gql.Query(repo.RepoHost(), "ReviewsForPullRequest", &query, variables)
		if err != nil {
			return err
		}

		pr.Reviews.Nodes = append(pr.Reviews.Nodes, query.Node.PullRequest.Reviews.Nodes...)
		pr.Reviews.TotalCount = len(pr.Reviews.Nodes)

		if !query.Node.PullRequest.Reviews.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Node.PullRequest.Reviews.PageInfo.EndCursor)
	}
```

**File:** pkg/cmd/pr/shared/finder.go (L504-518)
```go
	for {
		var query response
		err := gql.Query(repo.RepoHost(), "CommentsForPullRequest", &query, variables)
		if err != nil {
			return err
		}

		pr.Comments.Nodes = append(pr.Comments.Nodes, query.Node.PullRequest.Comments.Nodes...)
		pr.Comments.TotalCount = len(pr.Comments.Nodes)

		if !query.Node.PullRequest.Comments.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Node.PullRequest.Comments.PageInfo.EndCursor)
	}
```

**File:** pkg/cmd/issue/view/http.go (L33-49)
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

**File:** api/queries_org.go (L28-41)
```go
	var projects []RepoProject
	for {
		var query responseData
		err := client.Query(repo.RepoHost(), "OrganizationProjectList", &query, variables)
		if err != nil {
			return nil, err
		}

		projects = append(projects, query.Organization.Projects.Nodes...)
		if !query.Organization.Projects.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Organization.Projects.PageInfo.EndCursor)
	}
```

**File:** api/queries_projects_v2.go (L227-241)
```go
	var projectsV2 []ProjectV2
	for {
		var query responseData
		err := client.Query(repo.RepoHost(), "OrganizationProjectV2List", &query, variables)
		if err != nil {
			return nil, err
		}

		projectsV2 = append(projectsV2, query.Organization.ProjectsV2.Nodes...)

		if !query.Organization.ProjectsV2.PageInfo.HasNextPage {
			break
		}
		variables["endCursor"] = githubv4.String(query.Organization.ProjectsV2.PageInfo.EndCursor)
	}
```

**File:** pkg/cmd/label/http.go (L101-124)
```go
loop:
	for {
		var response listLabelsResponseData
		variables["limit"] = determinePageSize(opts.Limit - len(labels))
		err := apiClient.GraphQL(repo.RepoHost(), query, variables, &response)
		if err != nil {
			return nil, 0, err
		}

		totalCount = response.Repository.Labels.TotalCount

		for _, label := range response.Repository.Labels.Nodes {
			labels = append(labels, label)
			if len(labels) == opts.Limit {
				break loop
			}
		}

		if response.Repository.Labels.PageInfo.HasNextPage {
			variables["endCursor"] = response.Repository.Labels.PageInfo.EndCursor
		} else {
			break
		}
	}
```

**File:** pkg/cmd/pr/shared/lister.go (L114-143)
```go
loop:
	for {
		variables["limit"] = pageLimit
		var data response
		err := client.GraphQL(opts.BaseRepo.RepoHost(), query, variables, &data)
		if err != nil {
			return nil, err
		}
		prData := data.Repository.PullRequests
		res.TotalCount = prData.TotalCount

		for _, pr := range prData.Nodes {
			if _, exists := check[pr.Number]; exists && pr.Number > 0 {
				continue
			}
			check[pr.Number] = struct{}{}

			res.PullRequests = append(res.PullRequests, pr)
			if len(res.PullRequests) == limit {
				break loop
			}
		}

		if prData.PageInfo.HasNextPage {
			variables["endCursor"] = prData.PageInfo.EndCursor
			pageLimit = min(pageLimit, limit-len(res.PullRequests))
		} else {
			break
		}
	}
```
