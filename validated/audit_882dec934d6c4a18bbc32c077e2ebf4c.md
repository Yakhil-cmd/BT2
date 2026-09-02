### Title
Webhook signature verification keys on `repository.owner.login`/`organization.login` while all event handlers act on the independent, attacker-controlled `repository.full_name` field - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret/GitHub App to validate an inbound webhook against using `repository_owner`, which is read directly from the untrusted JSON body (`repository.owner.login` or `organization.login`). Every event handler, however, resolves *which* `Stack`/`Repository` to mutate using a completely different, equally attacker-controlled field: `repository.full_name`. Because nothing binds these two fields together, a request that is validly signed for organization A can carry a `repository.full_name` pointing at organization B's repository, letting the signing organization's credentials authorize actions against a repository it does not own.

### Finding Description
`verify_signature` computes the verifying key from the payload itself, not from anything cryptographically bound to the signature: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization:)` looks up a per-organization GitHub App config/secret when the installation is configured in multi-organization mode: [3](#0-2) 

Once the signature check passes, `create` dispatches the entire raw JSON body to the handlers: [4](#0-3) 

Every handler resolves the target `Stack`/`Repository` from `repository.full_name`, not from `repository.owner.login`: [5](#0-4) 

This is used, for example, by `PushHandler`, which loads the stacks for the resolved repository and enqueues a sync against an attacker-supplied SHA: [6](#0-5) [7](#0-6) 

The equality this breaks: the engine implicitly assumes `repository_owner (signed) == owner(repository.full_name) (acted upon)`, but nothing in the request enforces that. An attacker who can obtain a valid signature for organization A (e.g., they administer a legitimate, self-registered repository/webhook under org A on a multi-tenant Shipit instance, or org A's `webhook_secret` is left blank as the setup docs describe it as *optional*) can submit a body where `repository.owner.login` = A (so `verify_signature` passes) but `repository.full_name` = `B/victim-repo` (so the handler mutates B's stack). `Shipit.github(organization: repository_owner)` even swallows unknown organizations via `rescue Shipit::GithubOrganizationUnknown`, so the only requirement is that the *owner* field names some organization actually configured on the instance — the *full_name* field is completely free.

Contrast with `Hook::DeliverySigner`, which is the outbound analog and correctly signs the exact payload being delivered with a per-stack secret with no such field split.

### Impact Explanation
This crosses the "organization that authenticated versus the repository that is written" boundary called out in scope: a webhook validly signed for tenant A's organization can drive `GithubSyncJob`, commit/status ingestion, membership team/user creation, and pull-request/review-stack archiving/unarchiving/provisioning against tenant B's stacks. On a multi-tenant Shipit deployment (the documented multi-organization `secrets.github` configuration) this is a cross-repository/cross-tenant write achievable by a party who only controls credentials for a single, unrelated organization — matching the High-severity class "escalation into repository state control across tenant boundaries" and, depending on which handler is abused (e.g., forcing a sync/deploy state or membership/team changes), can reach unauthorized state changes on a stack outside the attacker's authorized organization.

### Likelihood Explanation
Exploitation requires only: (1) the target Shipit instance to run in multi-organization mode (`secrets.github` keyed by multiple orgs, as documented in `docs/setup.md`), and (2) the attacker to possess or forge a valid signature for any one configured organization — including the trivial case where that organization's `webhook_secret` is unset, since `verify_webhook_signature` returns `true` unconditionally when no secret is configured (`return true unless webhook_secret`, `lib/shipit/github_app.rb:76-83`). No Shipit session, GITHUB_TOKEN, or API client token is required, and the crafted JSON body is trivially constructed by any external, unprivileged party capable of POSTing to the public `/webhooks` endpoint.

### Recommendation
Bind signature-key selection to the same field the handlers act on, or reject payloads where the fields disagree:
- Compute `repository_owner` from `repository.full_name`'s owner segment (or require it to match `repository.owner.login`/`organization.login` before proceeding), so the organization used to select/verify the signing secret is provably the same organization whose repository will be mutated.
- Alternatively, once verified, re-derive the acted-upon organization strictly from the same trusted field used for verification and refuse to process events whose `repository.full_name` owner differs from `repository_owner`.
- Treat an absent/blank `webhook_secret` as "require no other organization can be impersonated by this org's requests," e.g., disallow full_name owners other than the verifying organization even when no secret is configured.

### Proof of Concept
1. Deploy Shipit with two organizations configured in `secrets.github`: `org-a` (attacker-administered, may have `webhook_secret` unset or known to the attacker) and `org-b` (victim, owns `org-b/victim-repo` registered as a Shipit stack).
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker computes/obtains a valid `X-Hub-Signature` for `org-a` (trivial if `org-a`'s `webhook_secret` is blank; otherwise obtainable via any legitimate webhook delivery the attacker controls for `org-a`).
4. POST to `/webhooks` with `X-Github-Event: push` and the above body/signature.
5. `verify_signature` resolves `Shipit.github(organization: "org-a")` and validates successfully.
6. `PushHandler` resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` and enqueues `GithubSyncJob` for `org-b`'s stack with the attacker-chosen `expected_head_sha`, mutating state on a repository the attacker does not control and never authenticated against.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-22)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
```
