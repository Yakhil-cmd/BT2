### Title
Webhook organization binding is not enforced when writing commit statuses, allowing cross-repository status forgery - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook against the GitHub App configuration of the organization named in the payload's `repository.owner.login` (or `organization.login`) field. Once that signature check passes, `StatusHandler#process` writes the CI status to *every* `Commit` record in the database whose `sha` matches the payload, with no re-check that the commit actually belongs to the organization/repository that was authenticated. In a multi-organization Shipit deployment (`Shipit.github_organizations`), a party that legitimately owns one configured GitHub App/organization can produce a validly signed `status` webhook for their own org while pointing the `sha` field at a commit belonging to a stack tracked under a *different* organization, forging a CI status on a repository they were never authenticated for.

### Finding Description
The verification step binds trust to the organization derived from the payload itself, before the payload's authenticity is known for anything beyond that: [1](#0-0) 

```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up per-organization webhook secrets, so the signature is only proven valid for whichever org name the attacker put in `repository.owner.login` — this is the credential the attacker legitimately controls (their own GitHub App installation's webhook secret).

Once verification passes, `StatusHandler#process` never re-checks that binding when applying the event: [2](#0-1) 

```
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

The lookup is a bare `Commit.where(sha: ...)` with no scoping to the `stack`/`repository` implied by the authenticated organization. Every `Commit` row across every stack/organization tracked by this Shipit instance is a candidate. This is exactly the "organization authenticated versus repository written" binding break: the webhook signature proves the payload came from *org A*, but the code that consumes the payload (`sha`) can mutate state belonging to *org B*.

### Impact Explanation
CI/commit statuses feed directly into deploy/merge safety gating (`required_statuses`, `blocking_statuses`, `StatusChecker`, continuous deployment eligibility). A forged `success` status on a foreign commit can help satisfy the status requirements Shipit checks before allowing a deploy or an automatic merge-queue merge on a stack the attacker never authenticated against — an unauthorized deploy/merge path, which is explicitly listed as accepted High/Critical impact in scope.

### Likelihood Explanation
Likelihood is Low-to-Moderate and is conditioned on the deployment being multi-tenant (multiple `github_organizations` configured on one Shipit instance, sharing one `Commit`/`Stack` table). This is a documented supported configuration (`Shipit.github_organizations`, `Shipit.github_app_config`), not a misconfiguration, so it isn't excluded under "host application not mounting the engine as documented." The attacker only needs legitimate ownership of any one of the configured GitHub App installations/orgs — not privileged access to the *target* repository, no `ApiClient` token, no session, and no knowledge of `webhook_secret` for the victim org. They do need to know the target commit's 40-hex `sha`, which is public for any commit visible on GitHub (commit pages, API, git history), so this is readily obtainable for public repos.

### Recommendation
Scope status/commit-status writes (and any other webhook-driven mutation keyed only by `sha`) to the repository/organization that was actually authenticated for the request, e.g. resolve `Stack`/`Commit` via the same `repository_owner`/`repository.name` used for signature verification, and reject or ignore matches whose owning stack's repository does not match the authenticated organization.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, `org-a` and `org-b`, each with its own `github.webhook_secret` (multi-tenant setup, per `Shipit.github_organizations`).
2. As the legitimate administrator of `org-a`'s GitHub App, compute a valid `X-Hub-Signature` for a `status` event payload using `org-a`'s webhook secret, with:
   - `repository.owner.login = "org-a"` (so `verify_signature` authenticates against `org-a`'s secret and passes)
   - `sha = <public sha of a commit belonging to a stack under org-b>`
   - `state = "success"`, `context = "<the context org-b's shipit.yml requires>"`
3. POST this payload to `/webhooks`.
4. `WebhooksController#verify_signature` succeeds (signed with `org-a`'s valid secret). `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the org-b commit, and calls `create_status_from_github!`, recording a fabricated `success` status on a repository the attacker never controlled or authenticated against, potentially unblocking an automated deploy/merge for `org-b`'s stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
