### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while event handlers act on the independent `repository.full_name` field, allowing cross-organization webhook forgery in multi-tenant deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to verify the HMAC signature against based on `repository_owner`, computed from `params.dig('repository','owner','login')` or `params.dig('organization','login')`. `Shipit::Webhooks::Handlers::Handler#stacks`, however, resolves the target `Repository`/`Stack` using a *different* payload field, `payload.dig('repository','full_name')`. Nothing ties these two fields together, so in Shipit's documented multi-organization setup, a webhook whose signature validly authenticates organization A can be crafted with a `repository.full_name` pointing at a repository owned by organization B, causing handlers to act on organization B's stack.

### Finding Description
Signature verification: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `repository.owner.login`, falling back to `organization.login`, and is used to pick the org-scoped `GitHubApp` instance (and its `webhook_secret`) via `Shipit.github(organization: repository_owner)`. This design is intended for Shipit's supported multi-tenant configuration, where each GitHub organization onboarded to a shared Shipit instance has its own `app_id`/`installation_id`/`webhook_secret` in `config/secrets.yml` (documented in `docs/setup.md`, "Using Multiple Github Applications").

Once the signature is accepted, the raw JSON `params` are dispatched unmodified to handlers: [3](#0-2) 

Handlers determine which `Stack`(s) to operate on using an entirely separate payload field: [4](#0-3) 

For example, the `push` handler syncs and can ultimately trigger deploys for whatever stack `repository.full_name` resolves to: [5](#0-4) [6](#0-5) 

There is no code anywhere in this path that checks `repository.owner.login`/`organization.login` (the field used to select the verifying secret) against the owner embedded in `repository.full_name` (the field used to select the affected `Stack`). This is the same class of bug as the referenced report: a payload field that is *acted on* (`repository.full_name`) is never actually covered by which secret was used to *authenticate* the request (`repository_owner`). The binding that should hold is:

`organization whose secret validated the signature == owner of the repository the handler mutates`

and this binding is never enforced.

### Impact Explanation
In a single-organization Shipit deployment this is not exploitable because there is only one webhook secret, so the two fields always agree for legitimately-signed traffic. However, in the officially documented multi-organization deployment mode, each onboarded organization possesses its own webhook secret (typically known to whoever configured that organization's GitHub App, i.e., a legitimate tenant of the shared Shipit instance, not the operator of other tenants' repos). Such a tenant — with knowledge only of their own organization's webhook secret and no access to another tenant's org, repo, or Shipit account — can compute a valid `X-Hub-Signature` for their own org (`repository.owner.login = OrgA`) while setting `repository.full_name = "OrgB/victim-repo"`. The request passes `verify_signature` (validated against OrgA's secret) but is routed by `Handler#stacks` to OrgB's `Stack`, using OrgB's own actual GitHub installation credentials (`stack.github_api`) to perform actions such as:
- Forcing `GithubSyncJob` to run for OrgB's stack via forged `push` events (`app/jobs/shipit/github_sync_job.rb`), and
- Feeding forged `status`/`check_suite` payload data that other handlers use to update commit CI state for OrgB's repository, which can unblock Shipit's merge queue / deploy gating and lead to an unauthorized deploy for OrgB.

This crosses a real trust boundary (organization authentication vs. repository written) using nothing more than the credentials of one unprivileged onboarded tenant, satisfying the "unauthorized deploy" / "cross-repository writes" impact bar.

### Likelihood Explanation
This requires the operator to run Shipit in the documented multi-organization mode (`docs/setup.md`, "Using Multiple Github Applications") with at least two onboarded organizations. Any tenant who has legitimately been given their own GitHub App/webhook secret for their organization (a normal, unprivileged customer relative to other tenants) can exploit this without any additional access. No `ApiClient` token, `github_access_token`, TLS interception, or privileged account is required — only the ability to send an arbitrary HTTP POST to the shared `/webhooks` endpoint with a body they can sign with their own secret.

### Recommendation
In `WebhooksController#verify_signature`/`create`, enforce that the organization used to select the verifying `webhook_secret` matches the owner encoded in `repository.full_name` (and `organization.login` if present) before dispatching to handlers — reject the request (e.g. `head(422)`) on mismatch. Alternatively, have `Handler#repository_name` derive the target repository strictly from the same `repository_owner` value already validated by signature verification, rather than independently trusting `repository.full_name`.

### Proof of Concept
1. Deploy Shipit with two organizations configured per `docs/setup.md`, e.g. `OrgA` and `OrgB`, each with a distinct `webhook_secret`, both with stacks already registered in Shipit.
2. As the (unprivileged, relative to OrgB) administrator of OrgA's GitHub App, craft a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(OrgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and successfully validates the signature using OrgA's secret (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`).
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves via `payload.dig('repository','full_name')` = `"OrgB/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), causing `GithubSyncJob`/`stack.sync_github` to run against OrgB's stack (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) — despite the signature never having been validated with OrgB's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
    end
```
