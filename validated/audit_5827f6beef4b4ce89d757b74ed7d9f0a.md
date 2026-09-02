### Title
Webhook signature is verified against the organization named in the payload while the handler acts on the repository named in the same payload, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret`) used to validate `X-Hub-Signature` based on an attacker-controlled field of the *same unverified* JSON body (`repository.owner.login` / `organization.login`), while every webhook `Handler` resolves the `Repository`/`Stack` to mutate using a *different* field of that same body (`repository.full_name`). Because Shipit supports multi-tenant GitHub App configuration (one `webhook_secret` per organization), a signature that is valid for organization A says nothing about the repository named in `repository.full_name`, which can belong to an unrelated organization B.

### Finding Description
The signature check is: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the untrusted request body before the signature has been validated, and is used to select which organization's `GitHubApp`/`webhook_secret` to check against via: [3](#0-2) 

Once the signature matches *some* org's secret, the request is accepted and dispatched to handlers unconditionally: [4](#0-3) 

However, every handler resolves the target `Stack`/`Repository` using a *different* field of the payload, `repository.full_name`, with no cross-check against `repository.owner.login`/`organization.login` that was used for signature selection: [5](#0-4) [6](#0-5) 

This breaks the binding: `organization whose webhook_secret authenticated the request == organization that owns the repository being written to`. An attacker who knows/controls the `webhook_secret` for any organization onboarded to a multi-tenant Shipit instance (organization A) can forge a signed payload where `repository.owner.login = "org-a"` (so verification succeeds against A's secret) but `repository.full_name = "org-b/victim-repo"` (a repository/stack belonging to a completely different, unrelated organization B tracked by the same Shipit instance). `PushHandler`, `StatusHandler`, and `CheckSuiteHandler` will all act on `org-b/victim-repo`'s `Stack` using only `repository.full_name`, without any relation to the organization that actually authenticated the request.

### Impact Explanation
This allows forging events against a repository/organization the attacker does not control, once they hold the secret of any other organization registered on the same Shipit instance:
- `PushHandler` queues `GithubSyncJob` with an attacker-chosen `expected_head_sha` against the foreign stack.
- `StatusHandler` creates arbitrary `Status` records (`state`, `context`, `target_url`) for commits on the foreign stack, which can influence CI-status–gated deploy decisions.
- `CheckSuiteHandler` triggers `RefreshCheckRunsJob` for the foreign stack.

Since commit statuses are used by Shipit to gate whether a deploy/merge is permitted, forging them can contribute to an unauthorized deploy path on a repository the attacker never had write access to, and does so by exploiting the organization-vs-repository binding gap, matching the "unauthorized deploy" high-impact category.

### Likelihood Explanation
Requires the attacker to already control (know the `webhook_secret` of) at least one organization onboarded to a shared, multi-tenant Shipit deployment (`Shipit.github_organizations`/per-org `secrets.github` config) — i.e., this only applies when the Shipit instance serves multiple organizations with separate webhook secrets rather than the single-org/global config. In that multi-tenant configuration, no repository write access, session, or `ApiClient` token to org B is needed; only the ability to sign and send a POST to `/webhooks` with a secret the attacker legitimately possesses for their own org A.

### Recommendation
In `verify_signature`, derive the organization used for secret lookup from the resolved `Repository`/`Stack` record (looked up via `repository.full_name`), not from an unauthenticated field of the payload, or explicitly assert `repository.owner.login`/`organization.login` matches the owner of the `Repository` that `repository.full_name` resolves to before dispatching handlers.

### Proof of Concept
1. Deploy Shipit in multi-tenant mode with two organizations configured, e.g. `secrets.github["org-a"]` (secret known to attacker) and `secrets.github["org-b"]` (owns `org-b/victim-repo`, tracked as a Shipit `Stack`).
2. Attacker builds a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefcafef00d",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a's webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` reads `repository_owner` → `"org-a"`, fetches `Shipit.github(organization: "org-a")`, and the signature check passes because the attacker used org A's real secret.
5. `PushHandler.call(params)` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")` [5](#0-4)  and enqueues `GithubSyncJob` against org B's stack, even though the request was never authenticated by org B's secret.

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

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
